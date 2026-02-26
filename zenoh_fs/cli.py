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
This is much more bandwidth efficient.
"""

from loguru import logger
import typer
import socket
import zenoh
from upath import UPath
import time
from fsspec.spec import AbstractFileSystem
from typing import Generator, Tuple, Callable
import hashlib
import secrets
import time
import heapq
import os
import threading

hostname = socket.gethostname()
logger.info(f"Running on {hostname}")


app = typer.Typer()

exposed_fs = None

class FileServer:

    def normalize_path(self, path):
        """Returns just the file path relative to the root of the exposed filesystem, removing the zenoh path and any read/write/ticket prefixes."""
        #Remove our node location
        path=path.removeprefix(self.zenoh_path)
        #Remove ticket if it exists
        path=path.removeprefix("/ticket")
        #Remove read/write if it exists. We only remove one, so if someone does read/write.txt they read the file at the path /write.txt
        if path.startswith("/read"):
            path=path.removeprefix("/read")
        elif path.startswith("/write"):
            path=path.removeprefix("/write")
        return path


    def generate_ticket(self, file_path, method):
        token = secrets.token_hex()
        ticket_path = f"{self.zenoh_path}/ticket/{method}/{file_path}"
        ticket = ticket_path + f"?token={token}"

        with self.ticket_lock:
            self.tickets[ticket] = time.time()
            expiry_time = time.time() + self.ticket_ttl
            heapq.heappush(self.ticket_heap, (expiry_time, ticket))
            logger.debug(f"Generated ticket for `{ticket_path}` with token {token[:4]}**** and expiry time {expiry_time}")
        return ticket

    def handle_read(self, query):
        method = query.parameters.get("method", "read")
        start = query.parameters.get("start", 0)
        end = query.parameters.get("end", None)
        chunk_size = query.parameters.get("chunk_size", 1024*1024) 
        file_path = self.normalize_path(query.key_expr)

        if method == "ticket":
            query.reply(self.generate_ticket(file_path, "read").encode())
            return
   
        if method == "hash":
            logger.info(f"Hashing file at {file_path}")
            hash_md5 = hashlib.md5()
            with self.exposed_fs.open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            query.reply(hash_md5.hexdigest().encode())
            return
        
        if method == "size":
            file_path = self.normalize_path(query.key_expr)
            logger.info(f"Getting size of file at {file_path}")
            size = self.exposed_fs.stat(file_path).st_size
            query.reply(str(size).encode())
            return
        
        if method == "list":
            dir_path = self.normalize_path(query.key_expr)
            logger.info(f"Listing directory at {dir_path}")
            entries = [entry.name for entry in self.exposed_fs.iterdir(dir_path)]
            query.reply("\n".join(entries).encode())
            return
        
        if method == "copy":
            """Copy a file from source to destination. The destination is another zenoh path that must be provided in the parameters as "dest". The source is the key expression of the query.
            We do this server side to avoid having to read the file into memory on the client side before writing it back to zenoh.
            """
            dest_path = query.parameters.get("dest", None)
            if dest_path is None:
                logger.error("No destination path provided for copy operation")
                query.reply(b"Error: No destination path provided for copy operation")
                return
            with self.exposed_fs.open(file_path, "rb") as f:
                f.seek(start)
                for _ in range(0, end-start, chunk_size):
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    
                    self.session.get(dest_path, payload=chunk, parameters={"method": "write", "start": start, "end": end})
            return

        if method == "read":

            #ToDo: must set a max chunk size to avoid memory issues.
            logger.info(f"Reading file at {file_path} with parameters: start={start}, end={end}, chunk_size={chunk_size}")
            
            with self.exposed_fs.open(file_path, "rb") as f:
                f.seek(start)
                for _ in range(0, end-start, chunk_size):
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    query.reply(chunk)

    def handle_write(self, query):
        method = query.parameters.get("method", "write")
        file_path = self.normalize_path(query.key_expr)
        start = query.parameters.get("start", 0)
        end = query.parameters.get("end", None)

        if method == "ticket":
            query.reply(self.generate_ticket(file_path, "write").encode())
            return

        if method == "delete":
            logger.info(f"Deleting file at {file_path}")
            self.exposed_fs.rm(file_path)
            return

        if method == "write":
            logger.info(f"Writing to file at {file_path} with parameters: start={start}, end={end}")
            with self.exposed_fs.open(file_path, "r+b") as f:
                f.seek(start)
                for _ in range(0, end-start, 1024*1024):
                    chunk = query.receive()
                    if not chunk:
                        break
                    f.write(chunk)
            return
        
        if method == "append":
            logger.info(f"Appending to file at {file_path}")
            with self.exposed_fs.open(file_path, "ab") as f:
                while True:
                    chunk = query.receive()
                    if not chunk:
                        break
                    f.write(chunk)
            return
        
        if method == "mkdir":
            logger.info(f"Creating directory at {file_path}")
            self.exposed_fs.mkdir(file_path)
            return
        
        if method == "rmdir":
            logger.info(f"Removing directory at {file_path}")
            self.exposed_fs.rmdir(file_path)
            return
        

    def handle_tickets(self, query):
        """Capability based security using tickets. A client must call read or write with "method=ticket" to generate a ticket for a specific file.
        A ticket consists of a path like "hostname/files/write/some/file.txt?ticket=12345" where 12345 is a random number. The server keeps track of valid tickets and their associated file paths.
        The client can then make calls on "hostname/files/ticket/write/some/file.txt?ticket=12345" to write to the file, and the server checks if the ticket is valid for that file before allowing the operation.

        This lets us leverage the existing ACL model of zenoh for read and write paths, file still allowing capability based security for higher performance reads and writes in a distributed system
        with multiple nodes.

        Internally the server maintains a set of valid tickets. Since the ticket filename is part of the ticket we don't need to store the file path associated with the ticket, we just need to check if the ticket is valid.

        The ticket does not handle fine grained permissions, just access to high level endpoints like read or write. If you want to give
        someone read but not hash, well you can't.
        """
        ticket = query.parameters.get("ticket", None)
        with self.ticket_lock:
            if not ticket in self.tickets:
                logger.warning(f"Invalid ticket {ticket} for query {query.key_expr}")
                query.reply_err(b"Error: Invalid ticket")
                return
            # Update last used time for ticket for garbage collection purposes
            self.tickets[ticket] = time.time()

        real_path = query.key_expr.removeprefix(self.zenoh_path + "/ticket/")
        action = real_path.split("/")[0]
        if action == "read":
            self.handle_read(query)
        elif action == "write":
            self.handle_write(query)
        else:
            logger.warning(f"Invalid action {action} in ticket query {query.key_expr}")
            query.reply_err(b"Error: Invalid action in ticket query")
        return
    
    def cleanup_tickets(self):
        """
        Checks the heap for expired tickets.
        Returns: seconds to sleep until the next expiration check.
        """
        now = time.time()
        next_sleep = self.ticket_ttl  # Default to ticket TTL if no tickets are in the heap.

        with self.ticket_lock:
            # Process all heap entries whose check_time has passed
            while self.ticket_heap and self.ticket_heap[0][0] <= now:
                check_time, ticket = heapq.heappop(self.ticket_heap)

                # Case 1: Ticket manually revoked or somehow missing
                if ticket not in self.tickets:
                    continue

                # Case 2: Check actual age relative to TTL
                actual_age = now - self.tickets[ticket]

                if actual_age >= self.ticket_ttl:
                    # EXPIRED: Remove the ticket
                    del self.tickets[ticket]
                    logger.debug(f"Garbage collected expired ticket: {ticket}")
                else:
                    # STILL ACTIVE: Ticket was accessed again after this check was scheduled.
                    # Reschedule it for its exact new expiration time.
                    new_expires = self.tickets[ticket] + self.ticket_ttl
                    heapq.heappush(self.ticket_heap, (new_expires, ticket))

            # If heap isn't empty, sleep until the next item is due
            if self.ticket_heap:
                next_sleep = self.ticket_heap[0][0] - now

        # Ensure we don't sleep negative time (logic error safety)
        return max(0, next_sleep)


    def expose(self, path: str, zenoh_path: str = f"{hostname}/files/"):
        self.tickets = {} # Set of valid tickets for capability based security, key is the full path of the ticket including the token. Value is when the ticket was
        # last used, for garbage collection purposes. ToDo: implement garbage collection of old tickets.
        self.ticket_ttl = int(os.getenv("TICKET_TTL", 10 * 60))
        self.ticket_heap = []
        self.ticket_lock = threading.Lock()

        self.zenoh_path = zenoh_path.removeprefix("/").removesuffix("/")
        self.exposed_fs = UPath(path).absolute()

        logger.info(f"Exposing {self.exposed_fs} at {self.zenoh_path}")

        self.session = zenoh.open(zenoh.Config())
        self.session.declare_queryable(self.zenoh_path + "read/**", self.handle_read)
        self.session.declare_queryable(self.zenoh_path + "write/**", self.handle_write)
        self.session.declare_queryable(self.zenoh_path + "ticket/**", self.handle_tickets)

        try:
            while True:

                sleep_time = self.cleanup_tickets()
                time.sleep(sleep_time)

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
