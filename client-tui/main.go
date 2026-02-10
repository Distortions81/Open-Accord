package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9101", "server address")
	keyPath := flag.String("key", "", "private key file path")
	contactsPath := flag.String("contacts", "", "contacts file path")
	profilePath := flag.String("profile", "", "profile file path")
	to := flag.String("to", "", "initial recipient login_id or alias")
	group := flag.String("group", "", "initial group label")
	channel := flag.String("channel", "", "initial channel label")
	flag.Parse()

	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("unable to resolve home directory: %v\n", err)
		os.Exit(1)
	}

	if strings.TrimSpace(*keyPath) == "" {
		*keyPath = filepath.Join(home, ".goaccord", "ed25519_key.json")
	}

	selectedStartupKeyPath, err := promptIdentityPath(home, *keyPath, false)
	if err != nil {
		fmt.Printf("identity selection failed: %v\n", err)
		os.Exit(1)
	}
	*keyPath = selectedStartupKeyPath

	if strings.TrimSpace(*contactsPath) == "" {
		*contactsPath = filepath.Join(home, ".goaccord", "contacts.json")
	}
	if strings.TrimSpace(*profilePath) == "" {
		*profilePath = filepath.Join(home, ".goaccord", "profiles", "profile-"+filepath.Base(strings.TrimSpace(*keyPath))+".json")
	}

	selectedKeyPath, priv, conn, enc, events, loginID, pubB64, err := connectWithIdentitySelection(*addr, home, *keyPath)
	if err != nil {
		fmt.Printf("connect/auth failed: %v\n", err)
		os.Exit(1)
	}
	*keyPath = selectedKeyPath

	contacts, err := loadContacts(*contactsPath)
	if err != nil {
		fmt.Printf("contacts load failed: %v\n", err)
		os.Exit(1)
	}

	displayName, profileText, nicknames, peerProfiles, err := loadProfile(*profilePath)
	if err != nil {
		fmt.Printf("profile load failed: %v\n", err)
		os.Exit(1)
	}
	if strings.TrimSpace(displayName) == "" {
		displayName = promptDisplayName(displayName)
		if err := saveProfile(*profilePath, displayName, profileText, nicknames, peerProfiles); err != nil {
			fmt.Printf("profile save failed: %v\n", err)
			os.Exit(1)
		}
	}

	in := textinput.New()
	in.Placeholder = "Type message or /help"
	in.Focus()
	in.CharLimit = 2048
	in.Width = 80

	m := model{
		input:           in,
		enc:             enc,
		events:          events,
		conn:            conn,
		priv:            priv,
		pubB64:          pubB64,
		loginID:         loginID,
		contactsPath:    *contactsPath,
		contacts:        contacts,
		friends:         make(map[string]struct{}),
		profilePath:     *profilePath,
		keyPath:         *keyPath,
		displayName:     displayName,
		profileText:     profileText,
		nicknames:       nicknames,
		peerProfiles:    peerProfiles,
		presence:        make(map[string]string),
		presenceTTL:     make(map[string]int),
		presenceVisible: true,
		presenceTTLSec:  defaultPresenceTTLSec,
		groups:          make(map[string]map[string]struct{}),
		pendingInvites:  make(map[string]pendingInvite),
		group:           strings.TrimSpace(*group),
		channel:         strings.TrimSpace(*channel),
		historyIndex:    -1,
		focusMode:       panelAll,
		panelChoices:    make(map[int]panelTarget),
	}

	m.addInfoEntry("connected to " + *addr)
	m.addInfoEntry("login_id: " + loginID)
	m.addInfoEntry("display name: " + displayName)
	m.addInfoEntry("contacts file: " + *contactsPath)
	m.addInfoEntry("profile file: " + *profilePath)
	m.addInfoEntry("/help for commands")
	if err := m.publishOwnProfile(); err != nil {
		m.addInfoEntry("profile publish failed: " + err.Error())
	}
	if err := m.sendPresenceKeepalive(); err != nil {
		m.addInfoEntry("presence keepalive failed: " + err.Error())
	}

	if initialTo := strings.TrimSpace(*to); initialTo != "" {
		if resolved, ok := m.resolveRecipient(initialTo); ok {
			m.to = resolved
			m.applyFocus(panelTarget{mode: panelDirect, direct: resolved})
			m.requestProfile(resolved)
			m.addInfoEntry("initial recipient: " + m.displayPeer(resolved))
		} else {
			m.addInfoEntry("unknown initial recipient: " + initialTo)
		}
	}

	for _, id := range m.contacts {
		m.requestProfile(id)
		m.requestPresence(id)
	}

	if strings.TrimSpace(*group) != "" && strings.TrimSpace(*channel) != "" {
		m.rememberGroupChannel(strings.TrimSpace(*group), strings.TrimSpace(*channel))
		m.applyFocus(panelTarget{mode: panelChannel, channel: strings.TrimSpace(*group) + "/" + strings.TrimSpace(*channel)})
	}

	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("tui failed: %v\n", err)
		_ = conn.Close()
		os.Exit(1)
	}
}
