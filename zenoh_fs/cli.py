"""
Zenoh FS exposes an arbitray universal pathlib compatible filesystem (local, s3, sshfs, ftp, etc) over zenoh.

We split the filesystem into two sub trees, read and write. This makes us compatible with the existing ACL model of zenoh,
allowing you to set ACLs like "hostname/files/write/var/log/myservice/**" to allow write access to a specific directory, of
allowing read access to a specific file with "hostname/files/read/var/log/myservice/myfile.log". Like all of zenoh this supports
wildcards in paths, allowing simple centralized policy-based access control to files and directories.

On the client side, we implement an fsspect compatible filesystem object backed by zenoh, which we leverage to implement a FUSE filesystem. 
This also allow you to use univeral pathlib to interact with our exposed filesystem as if it was a python pathlib object.

Read and write support "methods" as parameters. This is always based on our READ and WRITE paths. A hash operation doesn't modify data, so
it's a method on the read path, while delete is a method on the write path. This allows us to support operations other than just reading and writing bytes, while still being compatible with the existing ACL model of zenoh.

We also have a capability-based security system using "tickets" that allow you to pass your permission to read/write a file to another client, bypassing the ACLs for that specific file.
This is specifically useful for copy operations, where you can tell the fileserver itself to copy a file from source to destination, without having to read the file into memory on the client side before writing it back to zenoh.
This is much more bandwidth efficient. This lives at hostname/files/ticket/(read,write)/path/to/file?ticket=1234 .
"""

from loguru import logger
import typer
import socket
import zenoh
from fsspec.spec import AbstractFileSystem, AbstractBufferedFile
from typing import Generator, Tuple, Callable, Any
import io
import json

from zenoh_fs.FileServer import FileServer

hostname = socket.gethostname()
logger.info(f"Running on {hostname}")

app = typer.Typer()

def urlencode(params: dict[str, Any]) -> str:
    return ";".join(f"{key}={value}" for key, value in params.items())
class ZenohFile(AbstractBufferedFile):
    def __init__(
        self,
        fs: "ZenohFS",
        zenoh_session: zenoh.Session,
        zenoh_path: str,
        path: str,
        mode: str = "rb",
        **kwargs,
    ):
        self.session = zenoh_session
        self.zenoh_path = zenoh_path
        super().__init__(fs=fs, path=path, mode=mode, **kwargs)

    def _fetch_range(self, start: int, end: int) -> bytes:
        clean = self.path.strip("/")
        key = f"{self.zenoh_path}/read/{clean}" if clean else f"{self.zenoh_path}/read"
        selector = f"{key}?{urlencode({'method': 'read', 'start': start, 'end': end})}"
        logger.debug(f"Fetching range [{start}, {end}) from {selector}")

        chunks = []
        for reply in self.session.get(selector):
            if reply.ok is not None:
                chunks.append(bytes(reply.ok.payload))
            else:
                raise IOError(f"Error fetching range [{start}, {end}) from {key}: {reply.err.payload}")
        return b"".join(chunks)



class ZenohFS(AbstractFileSystem):
    protocol = "zenoh"

    def __init__(self, zenoh_path: str, **kwargs):
        super().__init__(**kwargs)
        self.zenoh_path = zenoh_path.removeprefix("/").removesuffix("/")
        self.session = zenoh.open(zenoh.Config())

    def _get(self, path: str, **params) -> bytes:
        clean = path.strip("/")
        key = f"{self.zenoh_path}/read/{clean}" if clean else f"{self.zenoh_path}/read"
        selector = f"{key}?{urlencode(params)}" if params else key

        logger.debug(f"Getting {selector}")
        
        results = []
        for reply in self.session.get(selector):
            if reply.ok is not None:
                results.append(bytes(reply.ok.payload))
            else:
                raise FileNotFoundError(f"Error from server for {key}: {reply.err.payload}")
        return b"".join(results)

    def ls(self, path: str, detail: bool = True, **kwargs: Any) -> list[dict[str, Any]] | list[str]:
        raw = self._get(path, method="list").decode()
        entries = raw.split("\n") if raw else []

        return entries

    def info(self, path: str, **kwargs: Any) -> dict[str, Any]:
        # Try size first — success means it's a file
        try:
            raw = self._get(path, method="info").decode()
            return json.loads(raw)
        except FileNotFoundError:
            raise
        except Exception as e:
            logger.warning(f"Error getting info for {path}: {e}")
            raise FileNotFoundError(f"Error getting info for {path}: {e}")

    def open(
        self,
        path: str,
        mode: str = "rb",
        block_size: int | None = None,
        cache_options: dict[str, Any] | None = None,
        compression: str | None = None,
        **kwargs: Any,
    ) -> io.RawIOBase | io.BufferedIOBase | io.TextIOBase:
        if "w" in mode or "a" in mode:
            raise NotImplementedError("ZenohFS is read-only")

        size = self.info(path)["size"]

        return ZenohFile(
            fs=self,
            zenoh_session=self.session,
            zenoh_path=self.zenoh_path,
            path=path,
            mode=mode,
            size=size,
            block_size=block_size or self.blocksize,
            cache_options=cache_options or {},
            **kwargs,
        )

@app.command()
def expose(path: str, zenoh_path: str = f"/{hostname}/files/"):
    FileServer().expose(path, zenoh_path)

@app.command()
def mount(zenoh_path: str, mount_point: str):
    import fsspec.fuse
    fsspec.fuse.run(ZenohFS(zenoh_path), path="/", mount_point=mount_point, foreground=True)


if __name__ == "__main__":
    app()
