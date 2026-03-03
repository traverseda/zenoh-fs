from zenoh_fs.FileServer import BaseFileServer


class ExecuteOnlyFileServer(BaseFileServer):
    """
    Exposes remote process execution over Zenoh using a queryable tree rooted at:

        {hostname}/execute/{user}/{command_path}

    Where {command_path} is the absolute path to the executable on the remote host,
    and {user} is the Unix user the process will run as. This maps naturally onto
    Zenoh's existing ACL model — you can grant fine-grained execution permissions
    using standard Zenoh key expression patterns, e.g.:

        {hostname}/execute/www-data/usr/bin/python3
        {hostname}/execute/traverseda/home/traverseda/scripts/**

    ## Key Expression Tree

        {hostname}/execute/{user}/{command_path}?method=spawn
        {hostname}/execute/{user}/session/{session_id}/stdin?method=stdin
        {hostname}/execute/{user}/session/{session_id}/stdout?method=stdout;offset=N
        {hostname}/execute/{user}/session/{session_id}/stderr?method=stderr;offset=N
        {hostname}/execute/{user}/session/{session_id}?method=status
        {hostname}/execute/{user}/session/{session_id}?method=kill

    ## Interaction Model

    The interaction model mirrors Unix pipes exactly:

    - **stdout and stderr are pull-based.** The client polls using a byte offset,
      exactly like reading from the read end of a pipe. The client increments the
      offset by the number of bytes received on each call. Since all output is via
      queryables with server-side session validation, a wildcard subscriber cannot
      intercept another session's streams.

    - **stdin is push-based.** The client writes to the server, exactly like writing
      to the write end of a pipe. Sending an empty payload closes stdin (EOF).
      stdin is the only operation that accepts tickets, allowing a different machine
      to pipe its stdout or stderr directly into this process's stdin without the
      data passing through the calling client.

    ## Cross-Machine Pipe Chains

    To replicate a Unix pipe chain across machines, pass stdin_sources and
    stdin_tickets to spawn. Each source may reference either the stdout or stderr
    stream of any upstream session, allowing arbitrary pipe topologies:

        # Equivalent to: cmd1 2>/tmp/err | cmd2 2>/tmp/err2; cat /tmp/err /tmp/err2 | cmd3
        #
        # 1. Spawn cmd1, get session_id_1
        # 2. Spawn cmd2 with stdin_sources=host1/.../session_id_1/stdout
        #    Get session_id_2
        # 3. Spawn cmd3 (log collector) with:
        #        stdin_sources=host1/.../session_id_1/stderr;host2/.../session_id_2/stderr
        #    Get session_id_3
        # 4. Poll session_id_2/stdout and session_id_3/stdout from the terminal.

    Each server pulls from the upstream session queryables using the provided
    tickets. Data flows between servers without passing through the calling client.

    ## Security Model

    Security is layered:

    - **Zenoh ACLs** control which clients can interact with the execute tree at all,
      using standard key expression patterns on the router config. This is coarse-grained
      and static — it controls who can spawn processes as a given user. <kcite ref="1"/>

    - **Session IDs** are unguessable hex tokens returned by spawn. All subsequent
      interaction with a session (stdin, stdout, stderr, kill, status) requires knowing
      the session ID, which acts as a capability token for that specific session.

    ## Why Queryables Instead of Pub/Sub

    Zenoh's ACL system is pattern-based and static. A client with permission to subscribe
    to `{hostname}/execute/{user}/session/**` could use a wildcard to intercept all
    sessions, bypassing the session ID capability model entirely. By keeping all I/O
    on queryables with server-side session validation, the server validates every request
    individually — wildcard queries cannot intercept other sessions' streams. <kcite ref="2"/>
    """

    def handle_execute(self, query):
        method = query.parameters.get("method", "spawn")
        file_path = self.normalize_path(query.key_expr)

        if method == "ticket":
            query.reply(query.key_expr, payload=self.generate_ticket(file_path, "execute").encode())
            return

        dispatch = {
            "spawn":  self._handle_spawn,
            "stdin":  self._handle_stdin,
            "stdout": self._handle_stdout,
            "stderr": self._handle_stderr,
            "status": self._handle_status,
            "kill":   self._handle_kill,
        }
        if method not in dispatch:
            raise ValueError(f"Invalid method {method} for execute query")
        dispatch[method](query, file_path)

    def _handle_spawn(self, query, command_path: str):
        """
        Start a process and return an unguessable session ID.

        The session ID acts as a capability token — all subsequent interaction
        with the process (stdin, stdout, stderr, kill, status) requires knowing it.
        The process runs as the user specified in the key expression path.

        Key:    {hostname}/execute/{user}/{command_path}?method=spawn
        Params:
            args            Additional CLI arguments, semicolon-separated.
            timeout         Maximum runtime in seconds before SIGKILL (optional).
            stdin_sources   Ordered, semicolon-separated list of session stream keys
                            to pull stdin from. Each entry may reference either the
                            stdout or stderr stream of any upstream session, allowing
                            arbitrary pipe topologies:

                                stdin_sources=host1/execute/user/session/abc/stdout;host1/execute/user/session/abc/stderr

                            Sources are consumed concurrently and interleaved in
                            arrival order, mirroring how Unix handles `cmd 2>&1 | next`.
                            Each source is drained until the upstream process exits
                            before stdin EOF is signalled to this process.

            stdin_tickets   Semicolon-separated read tickets corresponding to each
                            entry in stdin_sources, in the same order. Required if
                            any source session is access-controlled.

        Reply:  session_id (hex token)
        """
        raise NotImplementedError

    def _handle_stdin(self, query, session_path: str):
        """
        Write bytes to the process's stdin. The query payload is written directly
        to the process's stdin pipe. Sending an empty payload closes stdin (EOF),
        signalling end-of-input to the process.

        This is the only push-based operation, mirroring how Unix pipes work when
        writing to the write end of a pipe. Accepts tickets to allow upstream
        sessions on other machines to pipe their stdout or stderr directly into
        this process's stdin without the calling client handling the data.

        Key:    {hostname}/execute/{user}/session/{session_id}/stdin?method=stdin
        Reply:  empty on success
        """
        raise NotImplementedError

    def _handle_stdout(self, query, session_path: str):
        """
        Poll for stdout output since a given byte offset. Returns empty bytes if
        no new output is available yet. The client increments the offset on each
        call by the number of bytes received, mirroring how Unix pipes work when
        reading from the read end of a pipe.

        Key:    {hostname}/execute/{user}/session/{session_id}/stdout?method=stdout
        Params:
            offset      Byte offset to read from (default 0)
        Reply:  bytes from offset onward (may be empty if no new output yet)
        """
        raise NotImplementedError

    def _handle_stderr(self, query, session_path: str):
        """
        Poll for stderr output since a given byte offset. Identical semantics
        to stdout polling — stderr is a separate stream with its own independent
        offset. stderr may be used as a stdin_source for a downstream process,
        allowing log collection pipelines without the data passing through the
        calling client.

        Key:    {hostname}/execute/{user}/session/{session_id}/stderr?method=stderr
        Params:
            offset      Byte offset to read from (default 0)
        Reply:  bytes from offset onward (may be empty if no new output yet)
        """
        raise NotImplementedError

    def _handle_status(self, query, session_path: str):
        """
        Check whether the process is still running and retrieve its exit code
        if it has finished. The session remains queryable after exit until it
        is explicitly cleaned up or the server-side session TTL expires, allowing
        the client to drain any remaining stdout/stderr after the process exits.

        Key:    {hostname}/execute/{user}/session/{session_id}?method=status
        Reply:  JSON {"running": bool, "exit_code": int | null}
        """
        raise NotImplementedError

    def _handle_kill(self, query, session_path: str):
        """
        Send a signal to a running process. Knowing the session ID is the only
        authorization required — only the spawner can kill it. Defaults to
        SIGTERM to allow the process to clean up gracefully. Use SIGKILL to
        force-terminate immediately.

        Key:    {hostname}/execute/{user}/session/{session_id}?method=kill
        Params:
            signal      Signal name or number (default SIGTERM)
        Reply:  empty on success
        """
        raise NotImplementedError
