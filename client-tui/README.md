# client-tui

Interactive terminal UI client for GoAccord.

## Library stack
- `github.com/charmbracelet/bubbletea`
- `github.com/charmbracelet/bubbles`
- `github.com/charmbracelet/lipgloss`

## Run
```bash
go run ./client-tui -addr 127.0.0.1:9101
```

Optional flags:
- `-key <path>`: client private key file
- `-contacts <path>`: contacts file (default `~/.goaccord/contacts.json`)
- `-to <login_id|alias>`: initial recipient
- `-group <name>`: initial group label
- `-channel <name>`: initial channel label

## Commands
- `/help`
- `/to <login_id|alias>`
- `/use <login_id|alias>`
- `/contacts`
- `/remove-contact <alias>`
- `/group <name>`
- `/channel <name>`
- `/clearctx`
- `/whoami`
- `/friend-add <login_id|alias>`
- `/friend-accept <login_id|alias>`
- `/profile <text>`
- `/profile-get <login_id|alias>`
- `/presence <visible|invisible> [ttl_sec]`
- `/presence-check [login_id|alias]`
- `/channel-create <group> <channel> <public|private>`
- `/invite <login_id|alias>`
- `/channel-join <group> <channel>`
- `/channel-leave <group> <channel>`
- `/channel-send <text>`
- `/quit`

## Contacts behavior
- Contacts are created automatically when you interact with a `login_id` or receive packets from a user.
- Aliases default to short login-id prefixes; collisions get suffixes (`-2`, `-3`, ...).
- Use `/remove-contact <alias>` to delete.
