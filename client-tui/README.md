# client-tui

Interactive terminal UI client for GoAccord.

## Library stack
- `github.com/charmbracelet/bubbletea`
- `github.com/charmbracelet/bubbles`
- `github.com/charmbracelet/lipgloss`

## Run
```bash
go run ./client-tui -addr 127.0.0.1:9000
```

Optional flags:
- `-key <path>`: client private key file
- `-to <login_id>`: initial recipient
- `-group <name>`: initial group label
- `-channel <name>`: initial channel label

## Commands
- `/help`
- `/to <login_id>`
- `/group <name>`
- `/channel <name>`
- `/clearctx`
- `/whoami`
- `/quit`

## Notes
- Messages are signed with the same payload shape expected by the server.
- `group/channel` are currently labels on `send`/`deliver` packets.
