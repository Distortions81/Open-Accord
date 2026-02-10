# client-web

Simple local web UI client for goAccord.

## Run

```bash
go run ./client-web -addr 127.0.0.1:9101
```

Options:

- `-addr` protocol server address
- `-web` local HTTP listen address for the web UI (default `127.0.0.1:0`, ephemeral)
- `-key` identity key path
- `-contacts` contacts file path
- `-profile` profile file path
- `-open` auto-open browser (`true` default)

On startup it:

1. Prompts identity select/create.
2. Connects/authenticates to goAccord server.
3. Starts local HTTP server and serves a browser UI.

## UI capabilities

- DM send
- Friend add / friend accept
- Profile update (display name + profile text)
- Profile fetch for target
- Live chat/info event polling
- DM target list from contacts/friends
- Presence mode (`visible`/`invisible`) with periodic keepalive and TTL-based friend status checks

## Notes

- Uses same signed message/auth model as `client-tui`.
- Uses same compression behavior (`none` or `zlib`) for outgoing text payloads.
- Uses local read-merge-atomic-write for contacts/profile files to reduce multi-instance clobbering.
