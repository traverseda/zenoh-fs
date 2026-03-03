import hashlib
import heapq
import json
import os
import secrets
import threading
import time
import socket
from upath import UPath
from loguru import logger
import zenoh
import inspect

hostname = socket.gethostname()

class BaseFileServer:

    def normalize_path(self, path):
        """Returns just the file path relative to the root of the exposed filesystem, removing the zenoh path and any read/write/ticket prefixes."""
        #Remove our node location
        path = str(path)
        path=path.removeprefix(self.zenoh_path)
        #Remove ticket if it exists
        path=path.removeprefix("/ticket")
        #Remove read/write if it exists. We only remove one, so if someone does read/write.txt they read the file at the path /write.txt
        if path.startswith("/read"):
            path=path.removeprefix("/read")
        elif path.startswith("/write"):
            path=path.removeprefix("/write")
        return path if path else "/"


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

    def handle_read(self, query):
        raise NotImplementedError("handle_read must be implemented by subclass")
    def handle_write(self, query):
        raise NotImplementedError("handle_write must be implemented by subclass")
    def handle_execute(self, query):
        raise NotImplementedError("handle_execute must be implemented by subclass")


class ReadOnlyFileServer(BaseFileServer):

    def handle_read(self, query):
        method = query.parameters.get("method", "read")
        start = int(query.parameters.get("start", "0"))
        end = query.parameters.get("end", None)
        end = int(end) if end is not None else None
        chunk_size = int(query.parameters.get("chunk_size", str(1024*1024)))
        file_path = self.normalize_path(query.key_expr)

        logger.debug(f"Handling read query for {file_path} filesystem {self.exposed_fs} with parameters: {query.parameters}")

        if method == "ticket":
            ticket = self.generate_ticket(file_path, "read")
            query.reply(query.key_expr, payload=ticket.encode())
            #Only print the first 4 characters of the token for security reasons, since the ticket is a capability token that grants access to the file. The full ticket is only sent to the client that requested it, and is not logged.
            logger.debug(f"Generated ticket for {file_path} with token {ticket.split('=')[1][:4]}****")

            return

        if method == "hash":
            hash_type = query.parameters.get("hash_type", "sha256")
            try:
                h = hashlib.new(hash_type)
            except ValueError:
                raise ValueError(f"Unsupported hash type: {hash_type}. Available: {hashlib.algorithms_guaranteed}")

            with self.exposed_fs.open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    h.update(chunk)

            digest = f"{hash_type}:{h.hexdigest()}"
            logger.debug(f"Computed hash for {file_path}: {digest}")
            query.reply(query.key_expr, payload=digest.encode())
            return

        if method == "info":
            target = self.exposed_fs / file_path.lstrip("/")
            s = target.stat()
            data = {
                "name":    file_path,
                "size":    s.st_size,
                "type":    "directory" if target.is_dir() else "file",
                "mode":    s.st_mode,
                "uid":     s.st_uid,
                "gid":     s.st_gid,
                "nlink":   s.st_nlink,
                "atime":   s.st_atime,
                "mtime":   s.st_mtime,
                "ctime":   s.st_ctime,
            }
            query.reply(query.key_expr, payload=json.dumps(data).encode())
            return

        if method == "list":
            dir_path = self.normalize_path(query.key_expr)
            dir_path = self.exposed_fs / dir_path.lstrip("/")
            
            entries = [entry.name for entry in dir_path.iterdir()]
            query.reply(query.key_expr, payload="\n".join(entries).encode())
            return

        # if method == "copy":
        #     """Copy a file from source to destination. The destination is another zenoh path that must be provided in the parameters as "dest". The source is the key expression of the query.
        #     We do this server side to avoid having to read the file into memory on the client side before writing it back to zenoh.
        #     Note that for this to work, the destination and client must be on the same zenoh network and exposed using the same FUSE process.
        #     This is becouse linux only uses copy_file_range if the file descriptors of the source and destination are on the same filesystem.
        #     """
        #     #ToDo: destination *must* be a ticket, to avoid laundering the filesystems privileges.
        #     # We don't need to check if the destination ticket is valid here, because the write handler will check the ticket when we try to write to it. If the ticket is invalid, the write will simply fail and we won't have copied any data.
        #     dest_path = query.parameters.get("dest", None)
        #     if dest_path is None:
        #         logger.error("No destination path provided for copy operation")
        #         query.reply(b"Error: No destination path provided for copy operation")
        #         return
        #     with self.exposed_fs.open(file_path, "rb") as f:
        #         f.seek(start)
        #         for _ in range(0, end-start, chunk_size):
        #             chunk = f.read(chunk_size)
        #             if not chunk:
        #                 break

        #             self.session.get(dest_path, payload=chunk, parameters={"method": "write", "start": start, "end": end})
        #     return

        if method == "read":
            read_path = self.exposed_fs / file_path.lstrip("/")

            with read_path.open("rb") as f:
                f.seek(start)
                remaining = (end - start) if end is not None else None
                while True:
                    to_read = chunk_size if remaining is None else min(chunk_size, remaining)
                    chunk = f.read(to_read)
                    if not chunk:
                        break
                    query.reply(query.key_expr, payload=chunk)
                    if remaining is not None:
                        remaining -= len(chunk)
                        if remaining <= 0:
                            break
            return
        
        if method == "rename":
            raise NotImplementedError("Rename is not implemented yet. Please use the copy method to copy the file to the new location, then delete the old file.")
            """This is an expecially tricky operation to implement.
            We need three seperate permissions to rename a file. 
            First, we need read permission on the source file to read its contents and metadata. 
            Second, we need write permission on the destination path to create the new file. 
            Third, we need write permission on the source path to delete the old file after we've copied it to the new location.

            By implementing this as a seperate method we gain significant speed increases though, so it's worth the awkward ticket flow.
            """
        
        # query.reply_err(b"Error: Invalid method for read query")
        raise ValueError(f"Invalid method {method} for read query")

class WriteOnlyFileServer(BaseFileServer):


    def handle_write(self, query):

        # This is implemented as a get handler. No it should not be a put.
        # A get is zenoh's equivelent of an RPC call, where the client sends a request and the server yields.
        # A put is a publish-subscribe style message, and doesn't need to be explicitly acknowledged by the server. 
        # We want the client to know when the server has finished writing the file, so we use a get handler and yield chunks of the file as we write them.
        # This also puts backpressure on the client to avoid overwhelming the server with too much data at once,
        # and allows us to implement a simple flow control mechanism by only yielding when we're ready for more data.

        method = query.parameters.get("method", "write")
        file_path = self.normalize_path(query.key_expr)
        start = query.parameters.get("start", 0)
        end = query.parameters.get("end", None)

        if method == "ticket":
            query.reply(self.generate_ticket(file_path, "write").encode())
            return

        if method == "delete":
            logger.debug(f"Deleting file at {file_path}")
            self.exposed_fs.rm(file_path)
            return

        if method == "write":
            logger.debug(f"Writing to file at {file_path} with parameters: start={start}, end={end}")
            with self.exposed_fs.open(file_path, "r+b") as f:
                f.seek(start)
                for _ in range(0, end-start, 1024*1024):
                    chunk = query.receive()
                    if not chunk:
                        break
                    f.write(chunk)
            return

        if method == "append":
            logger.debug(f"Appending to file at {file_path}")
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
        query.reply(b"Error: Invalid method for write query")
        raise ValueError(f"Invalid method {method} for write query")


    def expose(self, path: str, zenoh_path: str = f"{hostname}/files/"):
        self.tickets = {} # Set of valid tickets for capability based security, key is the full path of the ticket including the token. Value is when the ticket was
        # last used, for garbage collection purposes. ToDo: implement garbage collection of old tickets.
        self.ticket_ttl = int(os.getenv("TICKET_TTL", 10 * 60))
        self.ticket_heap = [] # I do not understand how binary trees or heapq works.
        self.ticket_lock = threading.Lock()

        self.zenoh_path = zenoh_path.removeprefix("/").removesuffix("/")
        self.exposed_fs = UPath(path).absolute()

        logger.info(f"Exposing {self.exposed_fs} at {self.zenoh_path}")

        self.session = zenoh.open(zenoh.Config())
        self.session.declare_queryable(self.zenoh_path + "/read/**", self.handle_read)
        self.session.declare_queryable(self.zenoh_path + "/write/**", self.handle_write)
        self.session.declare_queryable(self.zenoh_path + "/ticket/**", self.handle_tickets)

        try:
            while True:
                sleep_time = self.cleanup_tickets()
                logger.debug(f"Sleeping for {sleep_time:.2f} seconds until next ticket cleanup")
                time.sleep(sleep_time)

        except KeyboardInterrupt:
            logger.info("Shutting down")


class FileServer(ReadOnlyFileServer, WriteOnlyFileServer):
    pass