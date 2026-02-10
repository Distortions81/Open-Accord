package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type Packet struct {
	Type    string `json:"type"`
	Role    string `json:"role,omitempty"`
	ID      string `json:"id,omitempty"`
	From    string `json:"from,omitempty"`
	To      string `json:"to,omitempty"`
	Body    string `json:"body,omitempty"`
	Group   string `json:"group,omitempty"`
	Channel string `json:"channel,omitempty"`
	Public  bool   `json:"public,omitempty"`
	Origin  string `json:"origin,omitempty"`
	Nonce   string `json:"nonce,omitempty"`
	PubKey  string `json:"pub_key,omitempty"`
	Sig     string `json:"sig,omitempty"`
}

type signedAction struct {
	Type    string `json:"type"`
	ID      string `json:"id"`
	From    string `json:"from"`
	To      string `json:"to,omitempty"`
	Body    string `json:"body,omitempty"`
	Group   string `json:"group,omitempty"`
	Channel string `json:"channel,omitempty"`
	Public  bool   `json:"public,omitempty"`
}

type keyFile struct {
	PrivateKey string `json:"private_key"`
}

type contactsFile struct {
	Contacts []savedContact `json:"contacts"`
}

type savedContact struct {
	Alias   string `json:"alias"`
	LoginID string `json:"login_id"`
}

type netMsg struct {
	pkt Packet
	err error
}

type localMsg struct {
	line string
}

type model struct {
	input textinput.Model

	enc     *json.Encoder
	events  <-chan netMsg
	conn    net.Conn
	priv    ed25519.PrivateKey
	pubB64  string
	loginID string
	counter atomic.Uint64

	to      string
	group   string
	channel string

	contactsPath string
	contacts     map[string]string

	lines  []string
	width  int
	height int
}

func waitNet(ch <-chan netMsg) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-ch
		if !ok {
			return netMsg{err: io.EOF}
		}
		return ev
	}
}

func logLine(s string) tea.Cmd {
	return func() tea.Msg { return localMsg{line: s} }
}

func (m model) Init() tea.Cmd {
	return tea.Batch(waitNet(m.events), textinput.Blink)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			_ = m.conn.Close()
			return m, tea.Quit
		case "enter":
			line := strings.TrimSpace(m.input.Value())
			m.input.SetValue("")
			if line == "" {
				return m, nil
			}
			if line == "/quit" {
				_ = m.conn.Close()
				return m, tea.Quit
			}
			if strings.HasPrefix(line, "/") {
				cmd := (&m).handleCommand(line)
				return m, cmd
			}

			if strings.TrimSpace(m.to) == "" {
				return m, logLine("set recipient with /to <login_id|alias>")
			}
			if err := m.sendSigned(Packet{Type: "send", To: m.to, Body: line, Group: m.group, Channel: m.channel}); err != nil {
				return m, tea.Batch(logLine("send error: "+err.Error()), tea.Quit)
			}
			out := fmt.Sprintf("[me -> %s] %s", shortID(m.to), line)
			if m.group != "" || m.channel != "" {
				out += fmt.Sprintf(" (%s/%s)", emptyDash(m.group), emptyDash(m.channel))
			}
			return m, logLine(out)
		}
	case netMsg:
		if msg.err != nil {
			if msg.err == io.EOF {
				return m, tea.Batch(logLine("connection closed"), tea.Quit)
			}
			return m, tea.Batch(logLine("network error: "+msg.err.Error()), tea.Quit)
		}
		_ = m.ensureContact(msg.pkt.From)
		_ = m.ensureContact(msg.pkt.To)
		switch msg.pkt.Type {
		case "deliver", "channel_deliver":
			line := fmt.Sprintf("[%s -> %s] %s", shortID(msg.pkt.From), shortID(msg.pkt.To), msg.pkt.Body)
			if msg.pkt.Group != "" || msg.pkt.Channel != "" {
				line += fmt.Sprintf(" (%s/%s)", emptyDash(msg.pkt.Group), emptyDash(msg.pkt.Channel))
			}
			if msg.pkt.Origin != "" {
				line += " via " + msg.pkt.Origin
			}
			m.lines = append(m.lines, stamp()+" "+line)
			return m, waitNet(m.events)
		case "friend_request", "friend_update", "channel_invite", "channel_update", "channel_joined":
			line := fmt.Sprintf("[%s] from=%s to=%s", msg.pkt.Type, shortID(msg.pkt.From), shortID(msg.pkt.To))
			if msg.pkt.Group != "" || msg.pkt.Channel != "" {
				line += fmt.Sprintf(" %s/%s", emptyDash(msg.pkt.Group), emptyDash(msg.pkt.Channel))
			}
			if msg.pkt.Body != "" {
				line += " " + msg.pkt.Body
			}
			m.lines = append(m.lines, stamp()+" "+line)
			return m, waitNet(m.events)
		case "error":
			m.lines = append(m.lines, stamp()+" server error: "+msg.pkt.Body)
			return m, waitNet(m.events)
		default:
			b, _ := json.Marshal(msg.pkt)
			m.lines = append(m.lines, stamp()+" server: "+string(b))
			return m, waitNet(m.events)
		}
	case localMsg:
		m.lines = append(m.lines, stamp()+" "+msg.line)
		return m, nil
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m model) View() string {
	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("63"))
	statusStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("247"))
	boxStyle := lipgloss.NewStyle().Border(lipgloss.NormalBorder()).Padding(0, 1)

	header := headerStyle.Render("goAccord TUI") + "  " +
		statusStyle.Render("login="+shortID(m.loginID)+" to="+emptyDash(shortID(m.to))+" group="+emptyDash(m.group)+" channel="+emptyDash(m.channel)+fmt.Sprintf(" contacts=%d", len(m.contacts)))

	maxLines := m.height - 6
	if maxLines < 4 {
		maxLines = 4
	}
	start := 0
	if len(m.lines) > maxLines {
		start = len(m.lines) - maxLines
	}
	body := strings.Join(m.lines[start:], "\n")
	if body == "" {
		body = "No messages yet. /help for commands."
	}
	panel := boxStyle.Width(maxInt(20, m.width-2)).Render(body)

	input := m.input.View()
	return header + "\n" + panel + "\n" + input
}

func (m *model) handleCommand(line string) tea.Cmd {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return nil
	}
	switch parts[0] {
	case "/help":
		return logLine("commands: /to <login_id|alias>, /contacts, /use <login_id|alias>, /remove-contact <alias>, /group <name>, /channel <name>, /clearctx, /whoami, /friend-add <login_id|alias>, /friend-accept <login_id|alias>, /channel-create <group> <channel> <public|private>, /invite <login_id|alias>, /channel-join <group> <channel>, /channel-leave <group> <channel>, /channel-send <text>, /quit")
	case "/to", "/use":
		if len(parts) < 2 {
			return logLine("usage: " + parts[0] + " <login_id|alias>")
		}
		target, ok := m.resolveRecipient(parts[1])
		if !ok {
			return logLine("unknown alias/login_id: " + strings.TrimSpace(parts[1]))
		}
		m.to = target
		return logLine("recipient set: " + shortID(m.to))
	case "/contacts":
		return logLine(m.formatContacts())
	case "/remove-contact":
		if len(parts) < 2 {
			return logLine("usage: /remove-contact <alias>")
		}
		alias := strings.TrimSpace(parts[1])
		if err := m.removeContact(alias); err != nil {
			return logLine("remove contact failed: " + err.Error())
		}
		return logLine("removed contact: " + alias)
	case "/group":
		if len(parts) < 2 {
			return logLine("usage: /group <name>")
		}
		m.group = strings.TrimSpace(parts[1])
		return logLine("group set: " + m.group)
	case "/channel":
		if len(parts) < 2 {
			return logLine("usage: /channel <name>")
		}
		m.channel = strings.TrimSpace(parts[1])
		return logLine("channel set: " + m.channel)
	case "/clearctx":
		m.group = ""
		m.channel = ""
		return logLine("group/channel context cleared")
	case "/whoami":
		return logLine("login_id: " + m.loginID)
	case "/friend-add":
		if len(parts) < 2 {
			return logLine("usage: /friend-add <login_id|alias>")
		}
		target, ok := m.resolveRecipient(parts[1])
		if !ok {
			return logLine("unknown alias/login_id: " + strings.TrimSpace(parts[1]))
		}
		if err := m.sendSigned(Packet{Type: "friend_add", To: target}); err != nil {
			return logLine("friend-add error: " + err.Error())
		}
		return logLine("friend request sent to " + shortID(target))
	case "/friend-accept":
		if len(parts) < 2 {
			return logLine("usage: /friend-accept <login_id|alias>")
		}
		target, ok := m.resolveRecipient(parts[1])
		if !ok {
			return logLine("unknown alias/login_id: " + strings.TrimSpace(parts[1]))
		}
		if err := m.sendSigned(Packet{Type: "friend_accept", To: target}); err != nil {
			return logLine("friend-accept error: " + err.Error())
		}
		return logLine("friend accepted: " + shortID(target))
	case "/channel-create":
		if len(parts) < 4 {
			return logLine("usage: /channel-create <group> <channel> <public|private>")
		}
		group := strings.TrimSpace(parts[1])
		channel := strings.TrimSpace(parts[2])
		mode := strings.ToLower(strings.TrimSpace(parts[3]))
		isPublic := mode == "public"
		if mode != "public" && mode != "private" {
			return logLine("channel mode must be public or private")
		}
		if err := m.sendSigned(Packet{Type: "channel_create", Group: group, Channel: channel, Public: isPublic}); err != nil {
			return logLine("channel-create error: " + err.Error())
		}
		m.group = group
		m.channel = channel
		return logLine(fmt.Sprintf("channel created: %s/%s (%s)", group, channel, mode))
	case "/invite":
		if len(parts) < 2 {
			return logLine("usage: /invite <login_id|alias> (uses current /group and /channel)")
		}
		if strings.TrimSpace(m.group) == "" || strings.TrimSpace(m.channel) == "" {
			return logLine("set /group and /channel first")
		}
		target, ok := m.resolveRecipient(parts[1])
		if !ok {
			return logLine("unknown alias/login_id: " + strings.TrimSpace(parts[1]))
		}
		if err := m.sendSigned(Packet{Type: "channel_invite", To: target, Group: m.group, Channel: m.channel}); err != nil {
			return logLine("invite error: " + err.Error())
		}
		return logLine(fmt.Sprintf("invited %s to %s/%s", shortID(target), m.group, m.channel))
	case "/channel-join":
		if len(parts) < 3 {
			return logLine("usage: /channel-join <group> <channel>")
		}
		group := strings.TrimSpace(parts[1])
		channel := strings.TrimSpace(parts[2])
		if err := m.sendSigned(Packet{Type: "channel_join", Group: group, Channel: channel}); err != nil {
			return logLine("channel-join error: " + err.Error())
		}
		m.group = group
		m.channel = channel
		return logLine(fmt.Sprintf("join requested: %s/%s", group, channel))
	case "/channel-leave":
		if len(parts) < 3 {
			return logLine("usage: /channel-leave <group> <channel>")
		}
		group := strings.TrimSpace(parts[1])
		channel := strings.TrimSpace(parts[2])
		if err := m.sendSigned(Packet{Type: "channel_leave", Group: group, Channel: channel}); err != nil {
			return logLine("channel-leave error: " + err.Error())
		}
		if m.group == group && m.channel == channel {
			m.group = ""
			m.channel = ""
		}
		return logLine(fmt.Sprintf("left: %s/%s", group, channel))
	case "/channel-send":
		if len(parts) < 2 {
			return logLine("usage: /channel-send <text> (uses current /group and /channel)")
		}
		if strings.TrimSpace(m.group) == "" || strings.TrimSpace(m.channel) == "" {
			return logLine("set /group and /channel first")
		}
		text := strings.TrimSpace(strings.TrimPrefix(line, parts[0]))
		if text == "" {
			return logLine("message text is required")
		}
		if err := m.sendSigned(Packet{Type: "channel_send", Group: m.group, Channel: m.channel, Body: text}); err != nil {
			return logLine("channel-send error: " + err.Error())
		}
		return logLine(fmt.Sprintf("[me -> %s/%s] %s", m.group, m.channel, text))
	default:
		return logLine("unknown command: " + parts[0])
	}
}

func (m *model) resolveRecipient(token string) (string, bool) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", false
	}
	if id, ok := m.contacts[token]; ok {
		return id, true
	}
	if looksLikeLoginID(token) {
		_ = m.ensureContact(token)
		return token, true
	}
	return "", false
}

func (m *model) formatContacts() string {
	if len(m.contacts) == 0 {
		return "no saved contacts"
	}
	aliases := make([]string, 0, len(m.contacts))
	for a := range m.contacts {
		aliases = append(aliases, a)
	}
	sort.Strings(aliases)
	lines := make([]string, 0, len(aliases)+1)
	lines = append(lines, "saved contacts:")
	for _, a := range aliases {
		lines = append(lines, fmt.Sprintf("  %s -> %s", a, m.contacts[a]))
	}
	return strings.Join(lines, "\n")
}

func (m *model) ensureContact(loginID string) error {
	loginID = strings.TrimSpace(loginID)
	if !looksLikeLoginID(loginID) || loginID == m.loginID {
		return nil
	}
	for _, id := range m.contacts {
		if id == loginID {
			return nil
		}
	}
	base := shortID(loginID)
	alias := base
	for i := 2; ; i++ {
		if _, exists := m.contacts[alias]; !exists {
			break
		}
		alias = fmt.Sprintf("%s-%d", base, i)
	}
	m.contacts[alias] = loginID
	return saveContacts(m.contactsPath, m.contacts)
}

func (m *model) removeContact(alias string) error {
	alias = strings.TrimSpace(alias)
	if alias == "" {
		return fmt.Errorf("alias required")
	}
	if _, ok := m.contacts[alias]; !ok {
		return fmt.Errorf("alias not found")
	}
	delete(m.contacts, alias)
	return saveContacts(m.contactsPath, m.contacts)
}

func (m *model) sendSigned(p Packet) error {
	p.ID = m.nextMessageID()
	p.From = m.loginID
	p.PubKey = m.pubB64
	sig, err := signAction(m.priv, p)
	if err != nil {
		return err
	}
	p.Sig = sig
	return m.enc.Encode(p)
}

func looksLikeLoginID(v string) bool {
	if len(v) != 64 {
		return false
	}
	for _, ch := range v {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	return true
}

func loadContacts(path string) (map[string]string, error) {
	out := make(map[string]string)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, err
	}
	var f contactsFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	for _, c := range f.Contacts {
		alias := strings.TrimSpace(c.Alias)
		id := strings.TrimSpace(c.LoginID)
		if alias == "" || !looksLikeLoginID(id) {
			continue
		}
		out[alias] = id
	}
	return out, nil
}

func saveContacts(path string, contacts map[string]string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	aliases := make([]string, 0, len(contacts))
	for a := range contacts {
		aliases = append(aliases, a)
	}
	sort.Strings(aliases)
	f := contactsFile{Contacts: make([]savedContact, 0, len(aliases))}
	for _, a := range aliases {
		f.Contacts = append(f.Contacts, savedContact{Alias: a, LoginID: contacts[a]})
	}
	payload, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, payload, 0o600)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func stamp() string {
	return time.Now().Format("15:04:05")
}

func shortID(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 12 {
		return s
	}
	return s[:12]
}

func emptyDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func loginIDForPubKey(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

func loadOrCreateKey(path string) (ed25519.PrivateKey, error) {
	if data, err := os.ReadFile(path); err == nil {
		var kf keyFile
		if err := json.Unmarshal(data, &kf); err != nil {
			return nil, err
		}
		raw, err := base64.StdEncoding.DecodeString(kf.PrivateKey)
		if err != nil {
			return nil, err
		}
		if len(raw) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("invalid private key size")
		}
		return ed25519.PrivateKey(raw), nil
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	payload, err := json.MarshalIndent(keyFile{PrivateKey: base64.StdEncoding.EncodeToString(priv)}, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		return nil, err
	}
	return priv, nil
}

func signAction(priv ed25519.PrivateKey, p Packet) (string, error) {
	msg, err := json.Marshal(signedAction{Type: p.Type, ID: p.ID, From: p.From, To: p.To, Body: p.Body, Group: p.Group, Channel: p.Channel, Public: p.Public})
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, msg)
	return base64.StdEncoding.EncodeToString(sig), nil
}

func runAuth(addr string, priv ed25519.PrivateKey) (net.Conn, *json.Encoder, <-chan netMsg, string, string, error) {
	pub := priv.Public().(ed25519.PublicKey)
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, nil, nil, "", "", err
	}
	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)

	if err := enc.Encode(Packet{Type: "hello", Role: "user", PubKey: pubB64}); err != nil {
		_ = conn.Close()
		return nil, nil, nil, "", "", err
	}

	var challenge Packet
	if err := dec.Decode(&challenge); err != nil {
		_ = conn.Close()
		return nil, nil, nil, "", "", err
	}
	if challenge.Type != "challenge" || strings.TrimSpace(challenge.Nonce) == "" {
		_ = conn.Close()
		return nil, nil, nil, "", "", fmt.Errorf("invalid challenge")
	}

	loginSig := ed25519.Sign(priv, []byte("login:"+challenge.Nonce))
	if err := enc.Encode(Packet{Type: "auth", PubKey: pubB64, Sig: base64.StdEncoding.EncodeToString(loginSig)}); err != nil {
		_ = conn.Close()
		return nil, nil, nil, "", "", err
	}

	var resp Packet
	if err := dec.Decode(&resp); err != nil {
		_ = conn.Close()
		return nil, nil, nil, "", "", err
	}
	if resp.Type != "ok" || strings.TrimSpace(resp.ID) == "" {
		_ = conn.Close()
		if resp.Type == "error" {
			return nil, nil, nil, "", "", fmt.Errorf("auth failed: %s", resp.Body)
		}
		return nil, nil, nil, "", "", fmt.Errorf("invalid auth response")
	}

	loginID := resp.ID
	if expected := loginIDForPubKey(pub); expected != loginID {
		_ = conn.Close()
		return nil, nil, nil, "", "", fmt.Errorf("login id mismatch")
	}

	events := make(chan netMsg, 32)
	go func() {
		defer close(events)
		for {
			var p Packet
			if err := dec.Decode(&p); err != nil {
				events <- netMsg{err: err}
				return
			}
			events <- netMsg{pkt: p}
		}
	}()

	return conn, enc, events, loginID, pubB64, nil
}

func (m *model) nextMessageID() string {
	n := m.counter.Add(1)
	prefix := m.loginID
	if len(prefix) > 12 {
		prefix = prefix[:12]
	}
	return fmt.Sprintf("%s-%d-%d", prefix, time.Now().UnixNano(), n)
}

func main() {
	addr := flag.String("addr", "127.0.0.1:9101", "server address")
	keyPath := flag.String("key", "", "private key file path")
	contactsPath := flag.String("contacts", "", "contacts file path")
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
	if strings.TrimSpace(*contactsPath) == "" {
		*contactsPath = filepath.Join(home, ".goaccord", "contacts.json")
	}

	priv, err := loadOrCreateKey(*keyPath)
	if err != nil {
		fmt.Printf("key load/create failed: %v\n", err)
		os.Exit(1)
	}
	contacts, err := loadContacts(*contactsPath)
	if err != nil {
		fmt.Printf("contacts load failed: %v\n", err)
		os.Exit(1)
	}

	conn, enc, events, loginID, pubB64, err := runAuth(*addr, priv)
	if err != nil {
		fmt.Printf("connect/auth failed: %v\n", err)
		os.Exit(1)
	}

	in := textinput.New()
	in.Placeholder = "Type message or /help"
	in.Focus()
	in.CharLimit = 2048
	in.Width = 80

	m := model{
		input:        in,
		enc:          enc,
		events:       events,
		conn:         conn,
		priv:         priv,
		pubB64:       pubB64,
		loginID:      loginID,
		contactsPath: *contactsPath,
		contacts:     contacts,
		group:        strings.TrimSpace(*group),
		channel:      strings.TrimSpace(*channel),
		lines: []string{
			stamp() + " connected to " + *addr,
			stamp() + " login_id: " + loginID,
			stamp() + " contacts file: " + *contactsPath,
			stamp() + " /help for commands",
		},
	}

	if initialTo := strings.TrimSpace(*to); initialTo != "" {
		if resolved, ok := m.resolveRecipient(initialTo); ok {
			m.to = resolved
			m.lines = append(m.lines, stamp()+" initial recipient: "+shortID(resolved))
		} else {
			m.lines = append(m.lines, stamp()+" unknown initial recipient: "+initialTo)
		}
	}

	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("tui failed: %v\n", err)
		_ = conn.Close()
		os.Exit(1)
	}
}
