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
	uiStatePath := uiStatePathForProfile(*profilePath)

	selectedKeyPath, priv, conn, enc, events, loginID, pubB64, err := connectWithIdentitySelection(*addr, home, *keyPath)
	if err != nil {
		fmt.Printf("connect/auth failed: %v\n", err)
		os.Exit(1)
	}
	*keyPath = selectedKeyPath
	e2eePath := e2eePathForKey(home, *keyPath)
	e2eeStatePath := e2eeStatePathForKey(home, *keyPath)
	e2eePriv, e2eePubB64, err := loadOrCreateE2EEKey(e2eePath)
	if err != nil {
		fmt.Printf("e2ee key load failed: %v\n", err)
		os.Exit(1)
	}
	peerE2EEMulti, friendKeyNonces, err := loadE2EEState(e2eeStatePath)
	if err != nil {
		fmt.Printf("e2ee state load failed: %v\n", err)
		os.Exit(1)
	}

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
	savedGroups, savedCtx, err := loadUIState(uiStatePath)
	if err != nil {
		fmt.Printf("ui state load failed: %v\n", err)
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
		e2ee:            e2eePriv,
		e2eeB64:         e2eePubB64,
		loginID:         loginID,
		contactsPath:    *contactsPath,
		contacts:        contacts,
		friends:         make(map[string]struct{}),
		profilePath:     *profilePath,
		uiStatePath:     uiStatePath,
		e2eePath:        e2eePath,
		e2eeStatePath:   e2eeStatePath,
		keyPath:         *keyPath,
		displayName:     displayName,
		profileText:     profileText,
		nicknames:       nicknames,
		peerProfiles:    peerProfiles,
		presence:        make(map[string]string),
		presenceTTL:     make(map[string]int),
		presenceVisible: true,
		presenceTTLSec:  defaultPresenceTTLSec,
		peerE2EEMulti:   peerE2EEMulti,
		friendKeyNonces: friendKeyNonces,
		e2eeIssues:      make(map[string]string),
		groups:          make(map[string]map[string]struct{}),
		pendingInvites:  make(map[string]pendingInvite),
		lastContext:     savedCtx,
		group:           strings.TrimSpace(*group),
		channel:         strings.TrimSpace(*channel),
		historyIndex:    -1,
		focusMode:       panelAll,
		panelChoices:    make(map[int]panelTarget),
		serverAddr:      *addr,
	}
	for _, g := range savedGroups {
		group := strings.TrimSpace(g.Name)
		if group == "" {
			continue
		}
		if len(g.Channels) == 0 {
			m.rememberGroupChannel(group, "default")
			continue
		}
		for _, ch := range g.Channels {
			m.rememberGroupChannel(group, ch)
		}
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

	appliedFromFlags := false
	if initialTo := strings.TrimSpace(*to); initialTo != "" {
		if resolved, ok := m.resolveRecipient(initialTo); ok {
			m.to = resolved
			m.applyFocus(panelTarget{mode: panelDirect, direct: resolved})
			m.requestProfile(resolved)
			m.requestPresence(resolved)
			m.addInfoEntry("initial recipient: " + m.displayPeer(resolved))
			appliedFromFlags = true
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
		appliedFromFlags = true
	}
	if !appliedFromFlags {
		if savedCtx.Mode == "group" && strings.TrimSpace(savedCtx.Group) != "" {
			ch := strings.TrimSpace(savedCtx.Channel)
			if ch == "" {
				ch = "default"
			}
			m.rememberGroupChannel(savedCtx.Group, ch)
			m.applyFocus(panelTarget{mode: panelChannel, channel: savedCtx.Group + "/" + ch})
		} else if savedCtx.Mode == "dm" && looksLikeLoginID(strings.TrimSpace(savedCtx.Target)) {
			target := strings.TrimSpace(savedCtx.Target)
			m.to = target
			m.applyFocus(panelTarget{mode: panelDirect, direct: target})
			m.requestProfile(target)
			m.requestPresence(target)
		}
	}

	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("tui failed: %v\n", err)
		_ = conn.Close()
		os.Exit(1)
	}
}
