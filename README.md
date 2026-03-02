A proof of concept demonstrating a filesystem exposed via zenoh and mounted
via fuse.

# Zenoh FS

Zenoh FS exposes arbitrary filesystems (local, S3, etc.) as interactive Zenoh resources, utilizing a strictly separated topic structure comprising read/ and write/ subtrees. This separation was chosen to align directly with Zenoh's native Access Control List (ACL) model, allowing administrators to enforce centralized, policy-based security (e.g., permitting writes to a directory while strictly locking reads to specific files) without implementing custom authorization layers. By treating non-destructive methods like hashing as read operations and modifying methods like deletion as write operations via query parameters, the system ensures consistent permission mapping.

To support a rich filesystem interface beyond simple byte streaming, Zenoh FS utilizes "methods" passed as query parameters to the read and write subtrees. Instead of creating separate endpoints for every file operation, the system determines the specific action to perform based on these parameters; for example, method=hash or method=list are routed to the read tree because they inspect data without modifying it, while method=delete, method=mkdir, or method=append are handled by the write tree. This design preserves the strict security separation of the read/write subtrees while enabling a comprehensive feature set—including directory listings, file hashing, and chunked reading—using a single, unified Queryable interface.

To enhance performance and enable complex workflows like server-side file copying, Zenoh FS implements a capability-based security system using "tickets." A ticket is a temporary, cryptographically random token that grants specific access rights to a file or directory, functioning as a short-lived capability that can bypass the broader ACL checks for its duration. This mechanism is particularly valuable for optimization; for example, when copying a large file between two remote nodes, a client can grant a source server a "write" ticket for the destination, allowing the servers to transfer data directly server-to-server. This approach maximizes bandwidth efficiency by avoiding the need to proxy the data through the client, all while maintaining strict security confinement for the specific operation.

## Supported filesystems

Filesystem support is built on [universal pathlib](https://universal-pathlib.readthedocs.io/en/latest/#currently-supported-filesystems).

This means paths like `ssh://user@example.com/home/youruser` work.

`memory://` is great for debugging. `./` will default to `local://./`.

There's also some s3fs, hadoop, huggingface, all kinds of stuff that is less
useful.
