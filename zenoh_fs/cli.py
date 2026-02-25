from loguru import logger
import typer
import socket
import zenoh
from upath import UPath
import time
import urllib
from fsspec.spec import AbstractFileSystem
from typing import Generator, Tuple, Callable
import hashlib

hostname = socket.gethostname()
logger.info(f"Running on {hostname}")


app = typer.Typer()

exposed_fs = None

class FileServer:
    def handler_read(self, query):
        start = query.parameters.get("start", 0)
        end = query.parameters.get("end", None)
        chunk_size = query.parameters.get("chunk_size", 1024*1024)
        #ToDo: must set a max chunk size to avoid memory issues.
        file_path = self.normalize_path(query.key_expr)
        logger.info(f"Reading file at {file_path} with parameters: start={start}, end={end}, chunk_size={chunk_size}")
        
        with self.exposed_fs.open(file_path, "rb") as f:
            f.seek(start)
            for _ in range(0, end-start, chunk_size):
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                query.reply(chunk)

    def handler_list(self, query):
        dir_path = self.normalize_path(query.key_expr)
        logger.info(f"Listing directory at {dir_path}")
        if self.exposed_fs.is_dir(dir_path):
            for entry in self.exposed_fs.iterdir(dir_path):
                query.reply(str(entry.name))
        else:
            query.reply_err(f"Error: {dir_path} is not a directory")

    def handler_write(self, query):
        file_path = self.normalize_path(query.key_expr)
        logger.info(f"Writing to file at {file_path}")
        with self.exposed_fs.open(file_path, "wb") as f:
            for chunk in query.payload:
                f.write(chunk)

    def deterministic_walk(self, path):
        """Walk the directory tree in a deterministic way by sorting the entries at each level."""
        for entry in sorted(path.iterdir()):
            yield entry
            if entry.is_dir():
                yield from self.deterministic_walk(entry)


    def handler_hash(self, query):
        """Generate a hash for a file or directory using a hash of hashes."""
        #ToDo: Not sure about this one. It breaks our ACL a bit, since it can access files
        #outside of the users tree.
        hash_algo = query.parameters.get("algo", "sha256")
        manifest = query.parameters.get("manifest", False)
        file_path = self.normalize_path(query.key_expr)
        logger.info(f"Hashing file at {file_path} with algorithm {hash_algo}")

        # Validate algorithm
        supported_algos = hashlib.algorithms_available
        if hash_algo not in supported_algos:
            query.reply_err(f"Error: Unsupported hash algorithm {hash_algo}. Supported algorithms are: {', '.join(supported_algos)}")
            return

        # Initialize the root hash object
        root_hash = hashlib.new(hash_algo)

        if self.exposed_fs.is_dir(file_path):
            # Process directory using deterministic_walk for sorted order
            for entry in self.deterministic_walk(self.exposed_fs / file_path):

                # Initialize a hash for this specific entry (file or folder)
                entry_hash = hashlib.new(hash_algo)

                # Hash the entry name (this ensures empty folders and filenames affect the root hash)
                entry_hash.update(entry.name.encode('utf-8'))

                if entry.is_file():
                    # Hash the file content
                    with entry.open("rb") as f:
                        while True:
                            chunk = f.read(1024*1024) # 1MB chunks
                            if not chunk:
                                break
                            entry_hash.update(chunk)

                # Update the root hash with the digest of the entry (The "Hash of Hashes" step)
                # This is efficient because we only pass the small digest (e.g., 32 bytes) 
                # to the parent hash, not the entire file content again.
                root_hash.update(entry_hash.digest())

                # Output manifest if requested
                if manifest:
                    query.reply(f"{entry}:{hash_algo}:{entry_hash.hexdigest()}")

        else:
            # Handle single file input
            entry_hash = hashlib.new(hash_algo)
            with self.exposed_fs.open(file_path, "rb") as f:
                while True:
                    chunk = f.read(1024*1024)
                    if not chunk:
                        break
                    entry_hash.update(chunk)

            root_hash.update(entry_hash.digest())

        # Final digest
        query.reply(f"{hash_algo}:{root_hash.hexdigest()}")


    def get_all_handlers(self) -> Generator[Tuple[str, Callable]]:
        """
        Get all methods that start with "handler_" and return their name (without the prefix) and the method itself as a generator.
        """
        for method_name in dir(self):
            if method_name.startswith("handler_"):
                operation = method_name.removeprefix("handler_")
                handler = getattr(self, method_name)
                yield operation, handler

    def normalize_path(self, path: str) -> str:
        """Normalize the path by removing the zenoh path prefix and any operation prefixes
        """
        path = urllib.parse(path).path
        path = path.removeprefix(self.zenoh_path)
        for prefix in (i[0] for i in self.get_all_handlers()):
            if path.startswith(prefix):
                path = path.removeprefix(prefix)
                break #We must break after the first match to avoid removing multiple prefixes
        return path                

    def expose(self, path: str, zenoh_path: str = f"{hostname}/files/"):
        self.exposed_fs = UPath(path).absolute()
        self.zenoh_path = zenoh_path.removeprefix("/").removesuffix("/")

        logger.info(f"Exposing {self.exposed_fs} at {self.zenoh_path}")
        #assert exposed_fs.exists(), f"Path {exposed_fs} does not exist"


        with zenoh.open(zenoh.Config()) as session:
            read_path = self.zenoh_path+"/read/**"
            for handler_name, handler in self.get_all_handlers():
                handler_name = self.zenoh_path + "/" + handler_name + "/**"
                session.declare_queryable(handler_name, handler)
                logger.debug(f"Declaring handler for {handler_name} at {handler}")

            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                logger.info("Shutting down")


class ZenohFS(AbstractFileSystem):
    def __init__(self, zenoh_path: str):
        self.zenoh_path = zenoh_path.removeprefix("/").removesuffix("/")
        self.session = zenoh.open(zenoh.Config())

    def open(self, path, mode="rb"):
        # Implement logic to read from zenoh
        pass

@app.command()
def expose(path: str, zenoh_path: str = f"/{hostname}/files/"):
    FileServer().expose(path, zenoh_path)

@app.command()
def mount(zenoh_path: str, mount_point: str):
    import fsspec
    ffspec.fuse.mount(ZenohFS(zenoh_path), mount_point)


if __name__ == "__main__":
    app()
