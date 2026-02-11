package main

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"goaccord/internal/netsec"
)

type Packet struct {
	Type        string `json:"type"`
	Role        string `json:"role,omitempty"`
	ID          string `json:"id,omitempty"`
	From        string `json:"from,omitempty"`
	To          string `json:"to,omitempty"`
	Body        string `json:"body,omitempty"`
	Compression string `json:"compression,omitempty"`
	USize       int    `json:"usize,omitempty"`
	Group       string `json:"group,omitempty"`
	Channel     string `json:"channel,omitempty"`
	Public      bool   `json:"public,omitempty"`
	Origin      string `json:"origin,omitempty"`
	Nonce       string `json:"nonce,omitempty"`
	PubKey      string `json:"pub_key,omitempty"`
	Sig         string `json:"sig,omitempty"`
}

type signedAction struct {
	Type        string `json:"type"`
	ID          string `json:"id"`
	From        string `json:"from"`
	To          string `json:"to,omitempty"`
	Body        string `json:"body,omitempty"`
	Compression string `json:"compression,omitempty"`
	USize       int    `json:"usize,omitempty"`
	Group       string `json:"group,omitempty"`
	Channel     string `json:"channel,omitempty"`
	Public      bool   `json:"public,omitempty"`
}

type keyFile struct {
	PrivateKey string `json:"private_key"`
}

type e2eeKeyFile struct {
	PrivateKey string `json:"private_key"`
}

type e2eeStateFile struct {
	PeerKeys []savedPeerE2EE    `json:"peer_keys,omitempty"`
	Nonces   []savedFriendNonce `json:"nonces,omitempty"`
}

type savedPeerE2EE struct {
	LoginID string `json:"login_id"`
	E2EEPub string `json:"e2ee_pub"`
	SeenAt  int64  `json:"seen_at,omitempty"`
}

type savedFriendNonce struct {
	LoginID string `json:"login_id"`
	Nonce   string `json:"nonce"`
	TS      int64  `json:"ts"`
}

type profileFile struct {
	DisplayName   string          `json:"display_name"`
	ProfileText   string          `json:"profile_text"`
	PeerNicknames []savedNickname `json:"peer_nicknames"`
	PeerProfiles  []savedProfile  `json:"peer_profiles"`
}

type chatContext struct {
	Mode    string `json:"mode,omitempty"` // dm|group
	Target  string `json:"target,omitempty"`
	Group   string `json:"group,omitempty"`
	Channel string `json:"channel,omitempty"`
}

type groupEntry struct {
	Name     string   `json:"name"`
	Channels []string `json:"channels,omitempty"`
}

type uiStateFile struct {
	Groups      []groupEntry `json:"groups,omitempty"`
	LastContext chatContext  `json:"last_context,omitempty"`
}

type profilePayload struct {
	Nickname    string `json:"nickname,omitempty"`
	ProfileText string `json:"profile_text,omitempty"`
}

type presenceKeepalivePayload struct {
	Visible bool `json:"visible"`
	TTLSec  int  `json:"ttl_sec"`
}

type presenceDataPayload struct {
	State     string `json:"state"`
	TTLSec    int    `json:"ttl_sec"`
	UpdatedAt int64  `json:"updated_at,omitempty"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
}

type friendKeyPayload struct {
	E2EEPub string `json:"e2ee_pub"`
	PubKey  string `json:"pub_key"`
	Sig     string `json:"sig"`
	TS      int64  `json:"ts"`
	Nonce   string `json:"nonce"`
}

type savedNickname struct {
	LoginID  string `json:"login_id"`
	Nickname string `json:"nickname"`
}

type savedProfile struct {
	LoginID     string `json:"login_id"`
	ProfileText string `json:"profile_text"`
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

type uiEntry struct {
	line    string
	direct  string
	channel string
}

type panelTarget struct {
	mode    string
	direct  string
	channel string
}

type pendingInvite struct {
	From      string
	Group     string
	Channel   string
	CreatedAt int64
}

const (
	compressionNone           = "none"
	compressionZlib           = "zlib"
	compressMinBytes          = 64
	panelAll                  = "all"
	panelDirect               = "direct"
	panelChannel              = "channel"
	presenceKeepaliveInterval = 5 * time.Minute
	minPresenceTTLSec         = 180
	maxPresenceTTLSec         = 900
	defaultPresenceTTLSec     = 390
	friendKeyMaxAge           = 30 * 24 * time.Hour
	maxPeerKeysPerLogin       = 8
)

type presenceTickMsg struct{}

type reconnectResultMsg struct {
	conn    net.Conn
	enc     *json.Encoder
	events  <-chan netMsg
	loginID string
	pubB64  string
	err     error
}

type model struct {
	input textinput.Model

	enc     *json.Encoder
	events  <-chan netMsg
	conn    net.Conn
	priv    ed25519.PrivateKey
	pubB64  string
	e2ee    *ecdh.PrivateKey
	e2eeB64 string
	loginID string
	counter atomic.Uint64

	to      string
	group   string
	channel string

	contactsPath      string
	contacts          map[string]string
	friends           map[string]struct{}
	profilePath       string
	uiStatePath       string
	e2eePath          string
	e2eeStatePath     string
	keyPath           string
	displayName       string
	profileText       string
	nicknames         map[string]string
	peerProfiles      map[string]string
	lastFriendRequest string
	presence          map[string]string
	presenceTTL       map[string]int
	presenceVisible   bool
	presenceTTLSec    int
	peerE2EEMulti     map[string][]string
	friendKeyNonces   map[string]map[string]int64
	e2eeIssues        map[string]string
	groups            map[string]map[string]struct{}
	pendingInvites    map[string]pendingInvite
	lastContext       chatContext

	infoEntries []string
	chatEntries []uiEntry
	width       int
	height      int

	history      []string
	historyIndex int
	historyDraft string

	focusMode    string
	focusDirect  string
	focusChannel string
	panelChoices map[int]panelTarget
	serverAddr   string
	reconnecting bool
	retryCount   int
	closing      bool
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

func schedulePresenceTick() tea.Cmd {
	return tea.Tick(presenceKeepaliveInterval, func(time.Time) tea.Msg {
		return presenceTickMsg{}
	})
}

func reconnectCmd(addr string, priv ed25519.PrivateKey, attempt int) tea.Cmd {
	return func() tea.Msg {
		if attempt > 0 {
			backoff := time.Second * time.Duration(1<<minInt(attempt, 5))
			time.Sleep(backoff)
		}
		conn, enc, events, loginID, pubB64, err := runAuth(addr, priv)
		if err != nil {
			return reconnectResultMsg{err: err}
		}
		return reconnectResultMsg{conn: conn, enc: enc, events: events, loginID: loginID, pubB64: pubB64}
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(waitNet(m.events), textinput.Blink, schedulePresenceTick())
}

func (m *model) addInfoEntry(line string) {
	m.infoEntries = append(m.infoEntries, stamp()+" "+line)
}

func (m *model) addChatEntry(name string, body string, direct string, channel string) {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "unknown"
	}
	body = strings.TrimSpace(body)
	m.chatEntries = append(m.chatEntries, uiEntry{line: fmt.Sprintf("%s %s: %s", stamp(), name, body), direct: direct, channel: channel})
}

func groupChannelKey(group string, channel string) string {
	return strings.TrimSpace(group) + "/" + strings.TrimSpace(channel)
}

func uiStatePathForProfile(profilePath string) string {
	return strings.TrimSpace(profilePath) + ".ui.json"
}

func (m *model) currentContext() chatContext {
	if strings.TrimSpace(m.group) != "" && strings.TrimSpace(m.channel) != "" {
		return chatContext{
			Mode:    "group",
			Group:   strings.TrimSpace(m.group),
			Channel: strings.TrimSpace(m.channel),
		}
	}
	if strings.TrimSpace(m.to) != "" {
		return chatContext{
			Mode:   "dm",
			Target: strings.TrimSpace(m.to),
		}
	}
	return chatContext{}
}

func (m *model) groupsList() []groupEntry {
	names := make([]string, 0, len(m.groups))
	for g := range m.groups {
		names = append(names, g)
	}
	sort.Strings(names)
	out := make([]groupEntry, 0, len(names))
	for _, g := range names {
		channels := make([]string, 0, len(m.groups[g]))
		for ch := range m.groups[g] {
			if strings.TrimSpace(ch) != "" {
				channels = append(channels, ch)
			}
		}
		sort.Strings(channels)
		out = append(out, groupEntry{Name: g, Channels: channels})
	}
	return out
}

func (m *model) persistUIState() {
	if strings.TrimSpace(m.uiStatePath) == "" {
		return
	}
	m.lastContext = m.currentContext()
	_ = saveUIState(m.uiStatePath, m.groupsList(), m.lastContext)
}

func (m *model) rememberGroupChannel(group string, channel string) {
	group = strings.TrimSpace(group)
	channel = strings.TrimSpace(channel)
	if group == "" || channel == "" {
		return
	}
	if m.groups[group] == nil {
		m.groups[group] = make(map[string]struct{})
	}
	m.groups[group][channel] = struct{}{}
	m.persistUIState()
}

func (m *model) displayPeer(loginID string) string {
	loginID = strings.TrimSpace(loginID)
	if loginID == "" {
		return "-"
	}
	if loginID == m.loginID && strings.TrimSpace(m.displayName) != "" {
		return m.displayName
	}
	if nick, ok := m.nicknames[loginID]; ok && strings.TrimSpace(nick) != "" {
		return nick
	}
	for alias, id := range m.contacts {
		if id == loginID {
			return alias
		}
	}
	return shortID(loginID)
}

func (m *model) requestProfile(target string) {
	target = strings.TrimSpace(target)
	if !looksLikeLoginID(target) || target == m.loginID {
		return
	}
	_ = m.sendSigned(Packet{Type: "profile_get", To: target})
}

func (m *model) requestPresence(target string) {
	target = strings.TrimSpace(target)
	if !looksLikeLoginID(target) || target == m.loginID {
		return
	}
	_ = m.enc.Encode(Packet{Type: "presence_get", To: target})
}

func normalizePresenceTTLSec(ttl int) int {
	if ttl < minPresenceTTLSec {
		return minPresenceTTLSec
	}
	if ttl > maxPresenceTTLSec {
		return maxPresenceTTLSec
	}
	return ttl
}

func (m *model) setPresence(loginID string, state string, ttl int) {
	loginID = strings.TrimSpace(loginID)
	state = strings.ToLower(strings.TrimSpace(state))
	if !looksLikeLoginID(loginID) {
		return
	}
	switch state {
	case "online", "offline", "invisible":
	default:
		state = "unknown"
	}
	m.presence[loginID] = state
	if ttl > 0 {
		m.presenceTTL[loginID] = normalizePresenceTTLSec(ttl)
	}
}

func (m *model) sendPresenceKeepalive() error {
	ttl := normalizePresenceTTLSec(m.presenceTTLSec)
	m.presenceTTLSec = ttl
	b, err := json.Marshal(presenceKeepalivePayload{Visible: m.presenceVisible, TTLSec: ttl})
	if err != nil {
		return err
	}
	return m.sendSigned(Packet{Type: "presence_keepalive", Body: string(b)})
}

func (m *model) publishOwnProfile() error {
	payload := profilePayload{Nickname: m.displayName, ProfileText: m.profileText}
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return m.sendSigned(Packet{Type: "profile_set", Body: string(b)})
}

func (m *model) applyFocus(t panelTarget) {
	switch t.mode {
	case panelAll:
		m.focusMode = panelAll
		m.focusDirect = ""
		m.focusChannel = ""
	case panelDirect:
		m.focusMode = panelDirect
		m.focusDirect = t.direct
		m.focusChannel = ""
		m.to = t.direct
		m.group = ""
		m.channel = ""
	case panelChannel:
		m.focusMode = panelChannel
		m.focusDirect = ""
		m.focusChannel = t.channel
		parts := strings.SplitN(t.channel, "/", 2)
		if len(parts) == 2 {
			m.group = parts[0]
			m.channel = parts[1]
		}
		m.to = ""
	}
	m.persistUIState()
}

func (m *model) shouldShow(e uiEntry) bool {
	switch m.focusMode {
	case panelDirect:
		return e.direct == m.focusDirect
	case panelChannel:
		return e.channel == m.focusChannel
	default:
		if strings.TrimSpace(m.group) != "" && strings.TrimSpace(m.channel) != "" {
			return e.channel == strings.TrimSpace(m.group)+"/"+strings.TrimSpace(m.channel)
		}
		if strings.TrimSpace(m.to) != "" {
			return e.direct == strings.TrimSpace(m.to)
		}
		return false
	}
}

func (m *model) commandNames() []string {
	return []string{
		"/help", "/to", "/use", "/contacts", "/remove-contact", "/friends",
		"/dm", "/identities", "/switchid",
		"/nick", "/myname", "/profile", "/profile-get",
		"/presence", "/presence-check",
		"/servers", "/invites", "/invite-accept",
		"/chat", "/chat-channel", "/panels", "/focus",
		"/group", "/channel", "/clearctx", "/whoami",
		"/friend-add", "/friend-accept", "/keys", "/e2ee-rotate",
		"/channel-create", "/invite", "/channel-join", "/channel-leave", "/channel-send",
		"/quit",
	}
}

func (m *model) recipientTokens() []string {
	set := make(map[string]struct{})
	for a, id := range m.contacts {
		set[a] = struct{}{}
		set[id] = struct{}{}
	}
	for id, nick := range m.nicknames {
		if looksLikeLoginID(id) && strings.TrimSpace(nick) != "" {
			set[nick] = struct{}{}
			set[id] = struct{}{}
		}
	}
	for id := range m.friends {
		set[id] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func completePrefix(prefix string, options []string) (string, []string) {
	matches := make([]string, 0)
	for _, o := range options {
		if strings.HasPrefix(o, prefix) {
			matches = append(matches, o)
		}
	}
	sort.Strings(matches)
	if len(matches) == 1 {
		return matches[0], matches
	}
	if len(matches) > 1 {
		common := matches[0]
		for _, m := range matches[1:] {
			for !strings.HasPrefix(m, common) {
				if len(common) == 0 {
					break
				}
				common = common[:len(common)-1]
			}
		}
		if len(common) > len(prefix) {
			return common, matches
		}
	}
	return prefix, matches
}

func (m *model) handleTab(line string) (string, string) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return line, "commands: " + strings.Join(m.commandNames(), " ")
	}
	if !strings.HasPrefix(trimmed, "/") {
		return line, ""
	}
	parts := strings.Fields(trimmed)
	if len(parts) == 0 {
		return line, ""
	}

	if len(parts) == 1 && !strings.HasSuffix(trimmed, " ") {
		completed, matches := completePrefix(parts[0], m.commandNames())
		if len(matches) > 1 {
			return completed + " ", "matches: " + strings.Join(matches, " ")
		}
		if completed != parts[0] {
			return completed + " ", ""
		}
		return line, ""
	}

	expectsRecipient := map[string]struct{}{
		"/to": {}, "/use": {}, "/chat": {}, "/dm": {}, "/friend-add": {}, "/friend-accept": {}, "/invite": {}, "/presence-check": {},
	}
	if _, ok := expectsRecipient[parts[0]]; ok {
		if len(parts) >= 2 && !strings.HasSuffix(trimmed, " ") {
			prefix := parts[len(parts)-1]
			completed, matches := completePrefix(prefix, m.recipientTokens())
			if len(matches) > 1 {
				return strings.TrimSuffix(trimmed, prefix) + completed, "matches: " + strings.Join(matches, " ")
			}
			if completed != prefix {
				return strings.TrimSuffix(trimmed, prefix) + completed, ""
			}
		}
	}
	return line, ""
}

func (m *model) pushHistory(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	if len(m.history) == 0 || m.history[len(m.history)-1] != line {
		m.history = append(m.history, line)
	}
	m.historyIndex = -1
	m.historyDraft = ""
}

func (m *model) historyUp() {
	if len(m.history) == 0 {
		return
	}
	if m.historyIndex == -1 {
		m.historyDraft = m.input.Value()
		m.historyIndex = len(m.history) - 1
	} else if m.historyIndex > 0 {
		m.historyIndex--
	}
	m.input.SetValue(m.history[m.historyIndex])
	m.input.CursorEnd()
}

func (m *model) historyDown() {
	if len(m.history) == 0 || m.historyIndex == -1 {
		return
	}
	if m.historyIndex < len(m.history)-1 {
		m.historyIndex++
		m.input.SetValue(m.history[m.historyIndex])
	} else {
		m.historyIndex = -1
		m.input.SetValue(m.historyDraft)
	}
	m.input.CursorEnd()
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.input.Width = maxInt(10, msg.Width-4)
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			m.closing = true
			if m.conn != nil {
				_ = m.conn.Close()
			}
			return m, tea.Quit
		case "up":
			m.historyUp()
			return m, nil
		case "down":
			m.historyDown()
			return m, nil
		case "tab":
			updated, note := m.handleTab(m.input.Value())
			m.input.SetValue(updated)
			m.input.CursorEnd()
			if note != "" {
				return m, logLine(note)
			}
			return m, nil
		case "enter":
			line := strings.TrimSpace(m.input.Value())
			m.input.SetValue("")
			if line == "" {
				return m, nil
			}
			m.pushHistory(line)
			if line == "/quit" {
				m.closing = true
				if m.conn != nil {
					_ = m.conn.Close()
				}
				return m, tea.Quit
			}
			if strings.HasPrefix(line, "/") {
				cmd := (&m).handleCommand(line)
				return m, cmd
			}

			directCtx := ""
			if strings.TrimSpace(m.group) != "" || strings.TrimSpace(m.channel) != "" {
				if strings.TrimSpace(m.group) == "" || strings.TrimSpace(m.channel) == "" {
					return m, logLine("set both /group and /channel, or use /chat for direct messages")
				}
				if err := m.sendSigned(Packet{Type: "channel_send", Group: m.group, Channel: m.channel, Body: line}); err != nil {
					return m, tea.Batch(logLine("send error: "+err.Error()), tea.Quit)
				}
				// Channel sends are echoed back by the server to the sender.
				// Avoid local append to prevent duplicate self-messages.
				return m, nil
			}

			if strings.TrimSpace(m.to) == "" {
				return m, logLine("set recipient with /to <login_id|alias> or /chat <login_id|alias>")
			}
			encryptedBody, err := m.encryptDirectMessage(m.to, line)
			if err != nil {
				return m, logLine("send error: " + err.Error())
			}
			if err := m.sendSigned(Packet{Type: "send", To: m.to, Body: encryptedBody}); err != nil {
				return m, tea.Batch(logLine("send error: "+err.Error()), tea.Quit)
			}
			if m.displayPeer(m.to) == shortID(m.to) {
				m.requestProfile(m.to)
			}
			directCtx = m.to
			m.addChatEntry(m.displayName, line, directCtx, "")
			return m, nil
		}
	case presenceTickMsg:
		cmds := []tea.Cmd{schedulePresenceTick()}
		if err := m.sendPresenceKeepalive(); err != nil {
			cmds = append(cmds, logLine("presence keepalive failed: "+err.Error()))
		}
		return m, tea.Batch(cmds...)
	case netMsg:
		if msg.err != nil {
			if m.closing {
				return m, tea.Quit
			}
			if errors.Is(msg.err, io.EOF) {
				m.addInfoEntry("connection closed; reconnecting...")
			} else {
				m.addInfoEntry("network error: " + msg.err.Error() + "; reconnecting...")
			}
			if !m.reconnecting {
				m.reconnecting = true
				m.retryCount = 0
				return m, reconnectCmd(m.serverAddr, m.priv, m.retryCount)
			}
			return m, nil
		}
		_ = m.ensureContact(msg.pkt.From)
		_ = m.ensureContact(msg.pkt.To)

		directCtx := ""
		channelCtx := ""
		if strings.TrimSpace(msg.pkt.Group) != "" && strings.TrimSpace(msg.pkt.Channel) != "" {
			channelCtx = msg.pkt.Group + "/" + msg.pkt.Channel
			m.rememberGroupChannel(msg.pkt.Group, msg.pkt.Channel)
		}

		switch msg.pkt.Type {
		case "deliver", "channel_deliver":
			if looksLikeLoginID(msg.pkt.From) {
				m.setPresence(msg.pkt.From, "online", defaultPresenceTTLSec)
			}
			line := msg.pkt.Body
			if msg.pkt.Type == "deliver" && strings.TrimSpace(msg.pkt.Group) == "" && strings.TrimSpace(msg.pkt.Channel) == "" && strings.TrimSpace(msg.pkt.From) != m.loginID {
				decodedDM, err := netsec.DecryptDM(m.e2ee, msg.pkt.Body)
				if err != nil {
					m.addInfoEntry("dm decrypt failed from " + m.displayPeer(msg.pkt.From) + ": " + err.Error())
					return m, waitNet(m.events)
				} else {
					line = decodedDM
				}
			}
			if msg.pkt.Origin != "" {
				m.addInfoEntry("message via " + msg.pkt.Origin)
			}
			if msg.pkt.Type == "deliver" {
				other := msg.pkt.From
				if msg.pkt.From == m.loginID {
					other = msg.pkt.To
				}
				directCtx = other
			}
			m.addChatEntry(m.displayPeer(msg.pkt.From), line, directCtx, channelCtx)
			return m, waitNet(m.events)
		case "ping":
			if looksLikeLoginID(msg.pkt.From) {
				m.setPresence(msg.pkt.From, "online", defaultPresenceTTLSec)
			}
			replyBody, _ := json.Marshal(map[string]any{"ping_id": msg.pkt.ID})
			if err := m.sendSigned(Packet{Type: "pong", To: msg.pkt.From, Body: string(replyBody)}); err != nil {
				m.addInfoEntry("pong send failed: " + err.Error())
			}
			return m, waitNet(m.events)
		case "pong":
			if looksLikeLoginID(msg.pkt.From) {
				m.setPresence(msg.pkt.From, "online", defaultPresenceTTLSec)
			}
			m.addInfoEntry("pong from " + m.displayPeer(msg.pkt.From))
			return m, waitNet(m.events)
		case "friend_request", "friend_update", "group_invite", "channel_update", "channel_joined":
			if looksLikeLoginID(msg.pkt.From) {
				m.setPresence(msg.pkt.From, "online", defaultPresenceTTLSec)
			}
			if msg.pkt.Type == "friend_request" && msg.pkt.To == m.loginID && looksLikeLoginID(msg.pkt.From) {
				m.lastFriendRequest = msg.pkt.From
				if k, err := m.consumeFriendKey(msg.pkt.From, msg.pkt.Body); err != nil {
					m.e2eeIssues[msg.pkt.From] = err.Error()
					m.addInfoEntry("friend key rejected from " + m.displayPeer(msg.pkt.From) + ": " + err.Error())
				} else if k != "" {
					_ = addPeerKeyWithLimit(m.peerE2EEMulti, msg.pkt.From, k, maxPeerKeysPerLogin)
					delete(m.e2eeIssues, msg.pkt.From)
					if err := m.persistE2EEState(); err != nil {
						m.addInfoEntry("e2ee state persist failed: " + err.Error())
					}
				}
				m.requestProfile(msg.pkt.From)
			}
			if msg.pkt.Type == "friend_update" {
				if looksLikeLoginID(msg.pkt.From) {
					if k, err := m.consumeFriendKey(msg.pkt.From, msg.pkt.Body); err != nil {
						m.e2eeIssues[msg.pkt.From] = err.Error()
						m.addInfoEntry("friend key rejected from " + m.displayPeer(msg.pkt.From) + ": " + err.Error())
					} else if k != "" {
						_ = addPeerKeyWithLimit(m.peerE2EEMulti, msg.pkt.From, k, maxPeerKeysPerLogin)
						delete(m.e2eeIssues, msg.pkt.From)
						if err := m.persistE2EEState(); err != nil {
							m.addInfoEntry("e2ee state persist failed: " + err.Error())
						}
					}
				}
				other := msg.pkt.From
				if other == m.loginID {
					other = msg.pkt.To
				}
				if looksLikeLoginID(other) && other != m.loginID {
					m.friends[other] = struct{}{}
				}
			}
			isInviteLikeUpdate := msg.pkt.Type == "channel_update" && strings.Contains(strings.ToLower(strings.TrimSpace(msg.pkt.Body)), "invite")
			if (msg.pkt.Type == "group_invite" || isInviteLikeUpdate) && strings.TrimSpace(msg.pkt.Group) != "" && strings.TrimSpace(msg.pkt.Channel) != "" {
				key := groupChannelKey(msg.pkt.Group, msg.pkt.Channel)
				m.pendingInvites[key] = pendingInvite{
					From:      strings.TrimSpace(msg.pkt.From),
					Group:     strings.TrimSpace(msg.pkt.Group),
					Channel:   strings.TrimSpace(msg.pkt.Channel),
					CreatedAt: time.Now().Unix(),
				}
				m.addInfoEntry(fmt.Sprintf("INVITE: %s from %s (use /invite-accept %s)", key, m.displayPeer(msg.pkt.From), key))
				m.addChatEntry("system", fmt.Sprintf("Invite to %s from %s (/invite-accept %s)", key, m.displayPeer(msg.pkt.From), key), "", "")
			}
			if msg.pkt.Type == "channel_joined" && strings.TrimSpace(msg.pkt.Group) != "" && strings.TrimSpace(msg.pkt.Channel) != "" {
				delete(m.pendingInvites, groupChannelKey(msg.pkt.Group, msg.pkt.Channel))
			}
			line := fmt.Sprintf("[%s] from=%s to=%s", msg.pkt.Type, m.displayPeer(msg.pkt.From), m.displayPeer(msg.pkt.To))
			if channelCtx != "" {
				line += " " + channelCtx
			}
			if msg.pkt.Body != "" {
				line += " " + msg.pkt.Body
			}
			m.addInfoEntry(line)
			return m, waitNet(m.events)
		case "profile_data":
			if looksLikeLoginID(msg.pkt.From) {
				m.setPresence(msg.pkt.From, "online", defaultPresenceTTLSec)
			}
			decoded, err := decodeTextBodyForClient(msg.pkt)
			if err != nil {
				m.addInfoEntry("profile decode failed: " + err.Error())
				return m, waitNet(m.events)
			}
			var prof profilePayload
			if err := json.Unmarshal([]byte(decoded), &prof); err != nil {
				m.addInfoEntry("profile parse failed")
				return m, waitNet(m.events)
			}
			nick := strings.TrimSpace(prof.Nickname)
			if nick != "" && looksLikeLoginID(msg.pkt.From) {
				m.nicknames[msg.pkt.From] = nick
				_ = saveProfile(m.profilePath, m.displayName, m.profileText, m.nicknames, m.peerProfiles)
			}
			line := "profile " + m.displayPeer(msg.pkt.From)
			if nick != "" {
				line += " nick=" + nick
			}
			peerText := strings.TrimSpace(prof.ProfileText)
			if peerText != "" && looksLikeLoginID(msg.pkt.From) {
				m.peerProfiles[msg.pkt.From] = peerText
				_ = saveProfile(m.profilePath, m.displayName, m.profileText, m.nicknames, m.peerProfiles)
				line += " bio=" + peerText
			} else if existing := strings.TrimSpace(m.peerProfiles[msg.pkt.From]); existing != "" {
				line += " bio=" + existing
			}
			m.addInfoEntry(line)
			return m, waitNet(m.events)
		case "presence_data":
			var pd presenceDataPayload
			if err := json.Unmarshal([]byte(strings.TrimSpace(msg.pkt.Body)), &pd); err == nil {
				m.setPresence(msg.pkt.From, pd.State, pd.TTLSec)
			} else {
				m.setPresence(msg.pkt.From, msg.pkt.Body, 0)
			}
			return m, waitNet(m.events)
		case "error":
			m.addInfoEntry("server error: " + msg.pkt.Body)
			return m, waitNet(m.events)
		default:
			b, _ := json.Marshal(msg.pkt)
			m.addInfoEntry("server: " + string(b))
			return m, waitNet(m.events)
		}
	case localMsg:
		m.addInfoEntry(msg.line)
		return m, nil
	case reconnectResultMsg:
		if m.closing {
			if msg.conn != nil {
				_ = msg.conn.Close()
			}
			return m, tea.Quit
		}
		if msg.err != nil {
			m.retryCount++
			m.addInfoEntry(fmt.Sprintf("reconnect failed (attempt %d): %v", m.retryCount, msg.err))
			return m, reconnectCmd(m.serverAddr, m.priv, m.retryCount)
		}
		if strings.TrimSpace(msg.loginID) != m.loginID {
			if msg.conn != nil {
				_ = msg.conn.Close()
			}
			m.retryCount++
			m.addInfoEntry("reconnect rejected: login_id mismatch")
			return m, reconnectCmd(m.serverAddr, m.priv, m.retryCount)
		}
		oldConn := m.conn
		m.conn = msg.conn
		m.enc = msg.enc
		m.events = msg.events
		m.pubB64 = msg.pubB64
		m.reconnecting = false
		m.retryCount = 0
		if oldConn != nil && oldConn != m.conn {
			_ = oldConn.Close()
		}
		m.addInfoEntry("reconnected")
		if err := m.publishOwnProfile(); err != nil {
			m.addInfoEntry("profile republish failed: " + err.Error())
		}
		if err := m.sendPresenceKeepalive(); err != nil {
			m.addInfoEntry("presence keepalive failed: " + err.Error())
		}
		for _, id := range m.contacts {
			m.requestProfile(id)
			m.requestPresence(id)
		}
		return m, waitNet(m.events)
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m model) View() string {
	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("63"))
	statusStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("247"))
	infoBoxStyle := lipgloss.NewStyle().Border(lipgloss.NormalBorder()).Padding(0, 1)
	chatBoxStyle := lipgloss.NewStyle().Border(lipgloss.NormalBorder()).Padding(0, 1)

	panelLabel := "all"
	switch m.focusMode {
	case panelDirect:
		panelLabel = "direct:" + m.displayPeer(m.focusDirect)
	case panelChannel:
		panelLabel = "channel:" + m.focusChannel
	}

	header := headerStyle.Render("goAccord TUI") + "  " +
		statusStyle.Render("panel="+panelLabel+" login="+m.displayPeer(m.loginID)+" to="+emptyDash(m.displayPeer(m.to))+" group="+emptyDash(m.group)+" channel="+emptyDash(m.channel)+fmt.Sprintf(" contacts=%d friends=%d invites=%d", len(m.contacts), len(m.friends), len(m.pendingInvites)))

	if m.width > 0 {
		m.input.Width = maxInt(10, m.width-4)
	}

	chatTitle := "select dm or server/channel"
	switch m.focusMode {
	case panelChannel:
		if strings.TrimSpace(m.focusChannel) != "" {
			chatTitle = strings.TrimSpace(m.focusChannel)
			break
		}
		fallthrough
	case panelAll:
		if strings.TrimSpace(m.group) != "" && strings.TrimSpace(m.channel) != "" {
			chatTitle = fmt.Sprintf("%s/%s", strings.TrimSpace(m.group), strings.TrimSpace(m.channel))
		} else if strings.TrimSpace(m.to) != "" {
			chatTitle = fmt.Sprintf("%s direct message", m.displayPeer(m.to))
		}
	case panelDirect:
		if strings.TrimSpace(m.focusDirect) != "" {
			chatTitle = fmt.Sprintf("%s direct message", m.displayPeer(m.focusDirect))
		}
	}

	visible := make([]string, 0, len(m.chatEntries))
	for _, e := range m.chatEntries {
		if m.shouldShow(e) {
			visible = append(visible, e.line)
		}
	}

	if m.width < 30 || m.height < 8 {
		compact := "Resize terminal for full view"
		if len(visible) > 0 {
			compact = visible[len(visible)-1]
		}
		return header + "\n" + compact + "\n" + m.input.View()
	}

	infoLines := m.height / 5
	if infoLines < 3 {
		infoLines = 3
	}
	if infoLines > 8 {
		infoLines = 8
	}

	maxLines := m.height - infoLines - 6
	if maxLines < 3 {
		maxLines = 3
	}
	start := 0
	if len(visible) > maxLines {
		start = len(visible) - maxLines
	}
	body := strings.Join(visible[start:], "\n")
	if body == "" {
		body = "No messages in this panel. /panels and /focus to switch."
	}

	maxInfo := infoLines - 1
	if maxInfo < 1 {
		maxInfo = 1
	}
	infoStart := 0
	if len(m.infoEntries) > maxInfo {
		infoStart = len(m.infoEntries) - maxInfo
	}
	infoBody := strings.Join(m.infoEntries[infoStart:], "\n")
	if strings.TrimSpace(infoBody) == "" {
		infoBody = "No info messages"
	}
	panelWidth := maxInt(20, m.width-2)
	infoPanel := infoBoxStyle.Width(panelWidth).Render(infoBody)

	chatPanel := chatBoxStyle.Width(panelWidth).Render("Chat: " + chatTitle + "\n" + body)

	input := m.input.View()
	return header + "\n" + infoPanel + "\n" + chatPanel + "\n" + input
}

func (m *model) buildPanelChoices() (string, map[int]panelTarget) {
	choices := make(map[int]panelTarget)
	lines := make([]string, 0)
	idx := 0
	choices[idx] = panelTarget{mode: panelAll}
	lines = append(lines, fmt.Sprintf("%d) all", idx))
	idx++

	directSet := make(map[string]struct{})
	for _, id := range m.contacts {
		if looksLikeLoginID(id) && id != m.loginID {
			directSet[id] = struct{}{}
		}
	}
	for id := range m.friends {
		directSet[id] = struct{}{}
	}
	for _, e := range m.chatEntries {
		if e.direct != "" {
			directSet[e.direct] = struct{}{}
		}
	}
	directs := make([]string, 0, len(directSet))
	for id := range directSet {
		directs = append(directs, id)
	}
	sort.Strings(directs)
	for _, id := range directs {
		choices[idx] = panelTarget{mode: panelDirect, direct: id}
		lines = append(lines, fmt.Sprintf("%d) direct %s", idx, m.displayPeer(id)))
		idx++
	}

	channelSet := make(map[string]struct{})
	if m.group != "" && m.channel != "" {
		channelSet[m.group+"/"+m.channel] = struct{}{}
	}
	for g, chs := range m.groups {
		for ch := range chs {
			channelSet[groupChannelKey(g, ch)] = struct{}{}
		}
	}
	for _, e := range m.chatEntries {
		if e.channel != "" {
			channelSet[e.channel] = struct{}{}
		}
	}
	channels := make([]string, 0, len(channelSet))
	for c := range channelSet {
		channels = append(channels, c)
	}
	sort.Strings(channels)
	for _, ch := range channels {
		choices[idx] = panelTarget{mode: panelChannel, channel: ch}
		lines = append(lines, fmt.Sprintf("%d) channel %s", idx, ch))
		idx++
	}
	m.panelChoices = choices
	return "panels:\n" + strings.Join(lines, "\n"), choices
}

func (m *model) parseFocusArg(arg string) (panelTarget, bool) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return panelTarget{}, false
	}
	if strings.EqualFold(arg, "all") {
		return panelTarget{mode: panelAll}, true
	}
	if n, err := strconv.Atoi(arg); err == nil {
		if t, ok := m.panelChoices[n]; ok {
			return t, true
		}
		return panelTarget{}, false
	}
	if strings.HasPrefix(arg, "@") {
		v, ok := m.resolveRecipient(strings.TrimPrefix(arg, "@"))
		if !ok {
			return panelTarget{}, false
		}
		return panelTarget{mode: panelDirect, direct: v}, true
	}
	if strings.HasPrefix(arg, "#") {
		v := strings.TrimPrefix(arg, "#")
		if strings.Count(v, "/") == 1 {
			return panelTarget{mode: panelChannel, channel: v}, true
		}
	}
	if v, ok := m.resolveRecipient(arg); ok {
		return panelTarget{mode: panelDirect, direct: v}, true
	}
	if strings.Count(arg, "/") == 1 {
		return panelTarget{mode: panelChannel, channel: arg}, true
	}
	return panelTarget{}, false
}

func (m *model) formatFriends() string {
	if len(m.friends) == 0 {
		return "no known friends"
	}
	ids := make([]string, 0, len(m.friends))
	for id := range m.friends {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	lines := make([]string, 0, len(ids)+1)
	lines = append(lines, "friends:")
	for _, id := range ids {
		lines = append(lines, fmt.Sprintf("  %s (%s) %s", m.displayPeer(id), id, m.presenceSummary(id)))
	}
	return strings.Join(lines, "\n")
}

func (m *model) friendTargets() []string {
	set := make(map[string]struct{})
	for id := range m.friends {
		if looksLikeLoginID(id) && id != m.loginID {
			set[id] = struct{}{}
		}
	}
	for _, id := range m.contacts {
		if looksLikeLoginID(id) && id != m.loginID {
			set[id] = struct{}{}
		}
	}
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		return strings.ToLower(m.displayPeer(ids[i])) < strings.ToLower(m.displayPeer(ids[j]))
	})
	return ids
}

func (m *model) formatDMList() string {
	ids := m.friendTargets()
	if len(ids) == 0 {
		return "no known friends/contacts"
	}
	lines := []string{"dm targets:"}
	for i, id := range ids {
		lines = append(lines, fmt.Sprintf("  %d) %s (%s) %s", i+1, m.displayPeer(id), id, m.presenceSummary(id)))
	}
	lines = append(lines, "use /dm <index|name|login_id>")
	return strings.Join(lines, "\n")
}

func (m *model) presenceSummary(loginID string) string {
	state := strings.TrimSpace(m.presence[loginID])
	if state == "" {
		state = "unknown"
	}
	ttl := m.presenceTTL[loginID]
	if ttl > 0 {
		return fmt.Sprintf("status=%s ttl=%ds", state, ttl)
	}
	return "status=" + state
}

func (m *model) sortedInviteKeys() []string {
	keys := make([]string, 0, len(m.pendingInvites))
	for k := range m.pendingInvites {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (m *model) formatServers() string {
	if len(m.groups) == 0 {
		return "no known servers/channels"
	}
	groups := make([]string, 0, len(m.groups))
	for g := range m.groups {
		groups = append(groups, g)
	}
	sort.Strings(groups)
	lines := []string{"servers/channels:"}
	for _, g := range groups {
		chs := make([]string, 0, len(m.groups[g]))
		for ch := range m.groups[g] {
			chs = append(chs, ch)
		}
		sort.Strings(chs)
		lines = append(lines, "  "+g+": "+strings.Join(chs, ", "))
	}
	return strings.Join(lines, "\n")
}

func (m *model) formatInvites() string {
	keys := m.sortedInviteKeys()
	if len(keys) == 0 {
		return "no pending channel invites"
	}
	lines := []string{"pending channel invites:"}
	for i, k := range keys {
		inv := m.pendingInvites[k]
		from := m.displayPeer(inv.From)
		lines = append(lines, fmt.Sprintf("  %d) %s from %s", i+1, k, from))
	}
	lines = append(lines, "accept with /invite-accept <index|group/channel>")
	return strings.Join(lines, "\n")
}

func (m *model) formatIdentityHelp() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "unable to resolve home directory for identity list"
	}
	items := listIdentityCandidates(home, m.keyPath)
	lines := []string{"identities (local):"}
	for i, c := range items {
		marker := " "
		if c.Path == m.keyPath {
			marker = "*"
		}
		label := strings.TrimSpace(c.Name)
		if label == "" {
			label = shortID(c.LoginID)
		}
		lines = append(lines, fmt.Sprintf("%s %d) %s [%s] (%s)", marker, i+1, label, shortID(c.LoginID), c.Path))
	}
	lines = append(lines, "startup always prompts for identity selection/create")
	lines = append(lines, "quick switch now: /switchid (exits client), then relaunch and pick identity")
	lines = append(lines, "or launch directly with: go run ./client-tui -key <identity-key-file>")
	return strings.Join(lines, "\n")
}

func (m *model) handleCommand(line string) tea.Cmd {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return nil
	}
	switch parts[0] {
	case "/help":
		return logLine("commands: /to /use /chat /dm /chat-channel /panels /focus /contacts /friends /remove-contact /identities /switchid /nick /myname /profile /profile-get /presence /presence-check /servers /invites /invite-accept /group /channel /clearctx /whoami /friend-add /friend-accept /keys /e2ee-rotate /channel-create /invite /channel-join /channel-leave /channel-send /quit")
	case "/to", "/use", "/chat", "/dm":
		if parts[0] == "/dm" && len(parts) < 2 {
			return logLine(m.formatDMList())
		}
		if len(parts) < 2 {
			return logLine("usage: " + parts[0] + " <login_id|alias>")
		}
		token := strings.TrimSpace(parts[1])
		target := ""
		ok := false
		if parts[0] == "/dm" {
			if idx, err := strconv.Atoi(token); err == nil {
				ids := m.friendTargets()
				if idx >= 1 && idx <= len(ids) {
					target = ids[idx-1]
					ok = true
				}
			}
		}
		if !ok {
			target, ok = m.resolveRecipient(token)
		}
		if !ok {
			if parts[0] == "/dm" {
				return logLine("unknown dm target: " + token + "\n" + m.formatDMList())
			}
			return logLine("unknown alias/login_id: " + strings.TrimSpace(parts[1]))
		}
		m.to = target
		m.group = ""
		m.channel = ""
		m.applyFocus(panelTarget{mode: panelDirect, direct: target})
		m.requestProfile(target)
		return logLine("chat target set: " + m.displayPeer(m.to))
	case "/chat-channel":
		if len(parts) < 3 {
			return logLine("usage: /chat-channel <group> <channel>")
		}
		m.group = strings.TrimSpace(parts[1])
		m.channel = strings.TrimSpace(parts[2])
		m.rememberGroupChannel(m.group, m.channel)
		m.to = ""
		m.applyFocus(panelTarget{mode: panelChannel, channel: m.group + "/" + m.channel})
		return logLine("channel target set: " + m.group + "/" + m.channel)
	case "/panels":
		list, _ := m.buildPanelChoices()
		return logLine(list)
	case "/focus":
		if len(parts) < 2 {
			return logLine("usage: /focus <index|all|@alias|#group/channel>")
		}
		t, ok := m.parseFocusArg(parts[1])
		if !ok {
			return logLine("unknown panel target")
		}
		m.applyFocus(t)
		return logLine("focus switched")
	case "/contacts":
		return logLine(m.formatContacts())
	case "/friends":
		return logLine(m.formatFriends())
	case "/servers":
		return logLine(m.formatServers())
	case "/invites":
		return logLine(m.formatInvites())
	case "/invite-accept":
		if len(parts) < 2 {
			return logLine("usage: /invite-accept <index|group/channel>")
		}
		token := strings.TrimSpace(parts[1])
		key := token
		if idx, err := strconv.Atoi(token); err == nil {
			keys := m.sortedInviteKeys()
			if idx < 1 || idx > len(keys) {
				return logLine("invite index out of range")
			}
			key = keys[idx-1]
		}
		inv, ok := m.pendingInvites[key]
		if !ok {
			return logLine("invite not found: " + key)
		}
		if err := m.sendSigned(Packet{Type: "channel_join", Group: inv.Group, Channel: inv.Channel}); err != nil {
			return logLine("invite-accept error: " + err.Error())
		}
		delete(m.pendingInvites, key)
		m.group = inv.Group
		m.channel = inv.Channel
		m.rememberGroupChannel(m.group, m.channel)
		m.applyFocus(panelTarget{mode: panelChannel, channel: m.group + "/" + m.channel})
		return logLine("invite accepted: " + key)
	case "/identities":
		return logLine(m.formatIdentityHelp())
	case "/switchid":
		m.addInfoEntry("switch identity: client exiting, relaunch to choose/create identity")
		m.closing = true
		if m.conn != nil {
			_ = m.conn.Close()
		}
		return tea.Quit
	case "/remove-contact":
		if len(parts) < 2 {
			return logLine("usage: /remove-contact <alias>")
		}
		alias := strings.TrimSpace(parts[1])
		if err := m.removeContact(alias); err != nil {
			return logLine("remove contact failed: " + err.Error())
		}
		return logLine("removed contact: " + alias)
	case "/nick":
		if len(parts) < 3 {
			return logLine("usage: /nick <login_id|alias> <nickname>")
		}
		target, ok := m.resolveRecipient(parts[1])
		if !ok {
			return logLine("unknown alias/login_id: " + strings.TrimSpace(parts[1]))
		}
		nick := strings.TrimSpace(strings.TrimPrefix(line, parts[0]+" "+parts[1]))
		if nick == "" {
			return logLine("nickname is required")
		}
		if err := m.setNickname(target, nick); err != nil {
			return logLine("nick update failed: " + err.Error())
		}
		return logLine("nickname set: " + m.displayPeer(target) + " (" + shortID(target) + ")")
	case "/myname":
		if len(parts) < 2 {
			return logLine("usage: /myname <name>")
		}
		name := strings.TrimSpace(strings.TrimPrefix(line, parts[0]))
		if name == "" {
			return logLine("display name is required")
		}
		if err := m.setDisplayName(name); err != nil {
			return logLine("myname update failed: " + err.Error())
		}
		return logLine("display name set: " + m.displayName)
	case "/profile":
		if len(parts) < 2 {
			return logLine("usage: /profile <text>")
		}
		text := strings.TrimSpace(strings.TrimPrefix(line, parts[0]))
		if text == "" {
			return logLine("profile text is required")
		}
		m.profileText = text
		if err := saveProfile(m.profilePath, m.displayName, m.profileText, m.nicknames, m.peerProfiles); err != nil {
			return logLine("profile update failed: " + err.Error())
		}
		payload := profilePayload{Nickname: m.displayName, ProfileText: m.profileText}
		b, err := json.Marshal(payload)
		if err != nil {
			return logLine("profile encode failed: " + err.Error())
		}
		if err := m.sendSigned(Packet{Type: "profile_set", Body: string(b)}); err != nil {
			return logLine("profile publish failed: " + err.Error())
		}
		return logLine("profile text updated")
	case "/profile-get":
		if len(parts) < 2 {
			return logLine("usage: /profile-get <login_id|alias>")
		}
		target, ok := m.resolveRecipient(parts[1])
		if !ok {
			return logLine("unknown alias/login_id: " + strings.TrimSpace(parts[1]))
		}
		if err := m.sendSigned(Packet{Type: "profile_get", To: target}); err != nil {
			return logLine("profile-get failed: " + err.Error())
		}
		return logLine("profile requested for " + m.displayPeer(target))
	case "/presence":
		if len(parts) == 1 {
			mode := "invisible"
			if m.presenceVisible {
				mode = "visible"
			}
			return logLine(fmt.Sprintf("presence: %s ttl=%ds (usage: /presence <visible|invisible> [ttl_sec %d-%d])", mode, m.presenceTTLSec, minPresenceTTLSec, maxPresenceTTLSec))
		}
		mode := strings.ToLower(strings.TrimSpace(parts[1]))
		visible := mode == "visible"
		if mode != "visible" && mode != "invisible" {
			return logLine("usage: /presence <visible|invisible> [ttl_sec]")
		}
		ttl := m.presenceTTLSec
		if len(parts) >= 3 {
			v, err := strconv.Atoi(strings.TrimSpace(parts[2]))
			if err != nil {
				return logLine("ttl_sec must be a number")
			}
			ttl = v
		}
		m.presenceVisible = visible
		m.presenceTTLSec = normalizePresenceTTLSec(ttl)
		if err := m.sendPresenceKeepalive(); err != nil {
			return logLine("presence update failed: " + err.Error())
		}
		return logLine(fmt.Sprintf("presence updated: %s ttl=%ds", mode, m.presenceTTLSec))
	case "/presence-check":
		if len(parts) >= 2 {
			target, ok := m.resolveRecipient(parts[1])
			if !ok {
				return logLine("unknown alias/login_id: " + strings.TrimSpace(parts[1]))
			}
			m.requestPresence(target)
			return logLine("presence requested for " + m.displayPeer(target))
		}
		ids := m.friendTargets()
		for _, id := range ids {
			m.requestPresence(id)
		}
		if len(ids) == 0 {
			return logLine("presence requested: no known targets")
		}
		return logLine(fmt.Sprintf("presence requested for %d targets", len(ids)))
	case "/group":
		if len(parts) < 2 {
			return logLine("usage: /group <name>")
		}
		m.group = strings.TrimSpace(parts[1])
		m.persistUIState()
		return logLine("group set: " + m.group)
	case "/channel":
		if len(parts) < 2 {
			return logLine("usage: /channel <name>")
		}
		m.channel = strings.TrimSpace(parts[1])
		m.persistUIState()
		return logLine("channel set: " + m.channel)
	case "/clearctx":
		m.to = ""
		m.group = ""
		m.channel = ""
		m.applyFocus(panelTarget{mode: panelAll})
		return logLine("message context cleared")
	case "/whoami":
		return logLine("login_id: " + m.loginID + " name=" + m.displayName)
	case "/friend-add":
		if len(parts) < 2 {
			return logLine("usage: /friend-add <login_id|alias>")
		}
		target, ok := m.resolveRecipient(parts[1])
		if !ok {
			return logLine("unknown alias/login_id: " + strings.TrimSpace(parts[1]))
		}
		if err := m.sendSigned(Packet{Type: "friend_add", To: target, Body: m.friendKeyBody()}); err != nil {
			return logLine("friend-add error: " + err.Error())
		}
		if m.displayPeer(target) == shortID(target) {
			m.requestProfile(target)
		}
		return logLine("friend request sent to " + m.displayPeer(target))
	case "/friend-accept":
		target := ""
		ok := false
		if len(parts) >= 2 {
			target, ok = m.resolveRecipient(parts[1])
			if !ok {
				return logLine("unknown alias/login_id: " + strings.TrimSpace(parts[1]))
			}
		} else if strings.TrimSpace(m.lastFriendRequest) != "" {
			target = m.lastFriendRequest
			ok = true
		} else {
			return logLine("usage: /friend-accept <login_id|alias> (or no arg to accept latest request)")
		}
		if !ok {
			return logLine("no pending friend request to accept")
		}
		if err := m.sendSigned(Packet{Type: "friend_accept", To: target, Body: m.friendKeyBody()}); err != nil {
			return logLine("friend-accept error: " + err.Error())
		}
		if m.displayPeer(target) == shortID(target) {
			m.requestProfile(target)
		}
		if target == m.lastFriendRequest {
			m.lastFriendRequest = ""
		}
		return logLine("friend accepted: " + m.displayPeer(target))
	case "/keys":
		return logLine(m.formatE2EEKeys())
	case "/e2ee-rotate":
		shared, err := m.rotateE2EEKey()
		if err != nil {
			return logLine("e2ee rotate failed: " + err.Error())
		}
		return logLine(fmt.Sprintf("e2ee key rotated; shared with %d friends", shared))
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
		m.rememberGroupChannel(group, channel)
		m.applyFocus(panelTarget{mode: panelChannel, channel: group + "/" + channel})
		return logLine("channel created: " + group + "/" + channel + " (" + mode + ")")
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
		if err := m.sendSigned(Packet{Type: "group_invite", To: target, Group: m.group, Channel: m.channel}); err != nil {
			return logLine("invite error: " + err.Error())
		}
		return logLine("invited " + m.displayPeer(target) + " to " + m.group + "/" + m.channel)
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
		m.rememberGroupChannel(group, channel)
		delete(m.pendingInvites, groupChannelKey(group, channel))
		m.applyFocus(panelTarget{mode: panelChannel, channel: group + "/" + channel})
		return logLine("join requested: " + group + "/" + channel)
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
			m.persistUIState()
		}
		return logLine("left: " + group + "/" + channel)
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
		// Channel sends are echoed back by the server to the sender.
		// Avoid local append to prevent duplicate self-messages.
		return nil
	default:
		return logLine("unknown command: " + parts[0])
	}
}

func (m *model) resolveRecipient(token string) (string, bool) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", false
	}
	for id, nick := range m.nicknames {
		if strings.EqualFold(strings.TrimSpace(nick), token) && looksLikeLoginID(id) {
			_ = m.ensureContact(id)
			return id, true
		}
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
		id := m.contacts[a]
		nick := strings.TrimSpace(m.nicknames[id])
		if nick != "" && nick != a {
			lines = append(lines, fmt.Sprintf("  %s -> %s nick=%s", a, id, nick))
		} else {
			lines = append(lines, fmt.Sprintf("  %s -> %s", a, id))
		}
	}
	return strings.Join(lines, "\n")
}

func (m *model) setNickname(loginID string, nickname string) error {
	loginID = strings.TrimSpace(loginID)
	nickname = strings.TrimSpace(nickname)
	if !looksLikeLoginID(loginID) {
		return fmt.Errorf("invalid login id")
	}
	if nickname == "" {
		return fmt.Errorf("nickname required")
	}
	m.nicknames[loginID] = nickname
	if err := m.ensureContact(loginID); err != nil {
		return err
	}
	if err := saveProfile(m.profilePath, m.displayName, m.profileText, m.nicknames, m.peerProfiles); err != nil {
		return err
	}
	payload := profilePayload{Nickname: m.displayName, ProfileText: m.profileText}
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return m.sendSigned(Packet{Type: "profile_set", Body: string(b)})
}

func (m *model) setDisplayName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("display name required")
	}
	m.displayName = name
	if err := saveProfile(m.profilePath, m.displayName, m.profileText, m.nicknames, m.peerProfiles); err != nil {
		return err
	}
	payload := profilePayload{Nickname: m.displayName, ProfileText: m.profileText}
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return m.sendSigned(Packet{Type: "profile_set", Body: string(b)})
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
	latest, err := loadContacts(m.contactsPath)
	if err != nil {
		return err
	}
	delete(latest, alias)
	for a, id := range m.contacts {
		latest[a] = id
	}
	if err := writeContactsAtomic(m.contactsPath, latest); err != nil {
		return err
	}
	m.contacts = latest
	return nil
}

func (m *model) sendSigned(p Packet) error {
	if m.enc == nil {
		return fmt.Errorf("not connected")
	}
	p.ID = m.nextMessageID()
	p.From = m.loginID
	p.PubKey = m.pubB64
	if strings.TrimSpace(p.Body) != "" {
		body, comp, usize, err := encodeBodyForSend(p.Body)
		if err != nil {
			return err
		}
		p.Body = body
		p.Compression = comp
		p.USize = usize
	}
	sig, err := signAction(m.priv, p)
	if err != nil {
		return err
	}
	p.Sig = sig
	return m.enc.Encode(p)
}

func (m *model) encryptDirectMessage(target string, plaintext string) (string, error) {
	target = strings.TrimSpace(target)
	recipientPubs := append([]string(nil), m.peerE2EEMulti[target]...)
	if len(recipientPubs) == 0 {
		return "", fmt.Errorf("missing verified recipient e2ee key; complete friend handshake")
	}
	return netsec.EncryptDMMulti(m.e2ee, recipientPubs, plaintext)
}

func (m *model) friendKeyBody() string {
	pub := strings.TrimSpace(m.e2eeB64)
	signingPub := strings.TrimSpace(m.pubB64)
	signingPriv := m.priv
	if pub == "" {
		return ""
	}
	ts := time.Now().UnixMilli()
	nonce, err := randomNonceB64(16)
	if err != nil {
		return ""
	}
	sig := ed25519.Sign(signingPriv, friendKeyMessage(pub, ts, nonce))
	b, err := json.Marshal(friendKeyPayload{
		E2EEPub: pub,
		PubKey:  signingPub,
		Sig:     base64.StdEncoding.EncodeToString(sig),
		TS:      ts,
		Nonce:   nonce,
	})
	if err != nil {
		return ""
	}
	return string(b)
}

func randomNonceB64(n int) (string, error) {
	if n <= 0 {
		n = 16
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}

func friendKeyMessage(e2eePub string, ts int64, nonce string) []byte {
	return []byte(fmt.Sprintf("friend-e2ee-key-v1:%s:%d:%s", strings.TrimSpace(e2eePub), ts, strings.TrimSpace(nonce)))
}

func parseFriendKey(body string, from string) (friendKeyPayload, bool, error) {
	var payload friendKeyPayload
	if err := json.Unmarshal([]byte(strings.TrimSpace(body)), &payload); err != nil {
		return friendKeyPayload{}, false, nil
	}
	e2eePub := strings.TrimSpace(payload.E2EEPub)
	signingPubB64 := strings.TrimSpace(payload.PubKey)
	sigB64 := strings.TrimSpace(payload.Sig)
	nonce := strings.TrimSpace(payload.Nonce)
	if e2eePub == "" && signingPubB64 == "" && sigB64 == "" && nonce == "" && payload.TS == 0 {
		return friendKeyPayload{}, false, nil
	}
	if e2eePub == "" || signingPubB64 == "" || sigB64 == "" || nonce == "" || payload.TS <= 0 {
		return friendKeyPayload{}, true, fmt.Errorf("incomplete key payload")
	}
	pubRaw, err := base64.StdEncoding.DecodeString(signingPubB64)
	if err != nil || len(pubRaw) != ed25519.PublicKeySize {
		return friendKeyPayload{}, true, fmt.Errorf("invalid pubkey")
	}
	if loginIDForPubKey(pubRaw) != strings.TrimSpace(from) {
		return friendKeyPayload{}, true, fmt.Errorf("identity mismatch")
	}
	sigRaw, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || len(sigRaw) != ed25519.SignatureSize {
		return friendKeyPayload{}, true, fmt.Errorf("invalid signature encoding")
	}
	if !ed25519.Verify(ed25519.PublicKey(pubRaw), friendKeyMessage(e2eePub, payload.TS, nonce), sigRaw) {
		return friendKeyPayload{}, true, fmt.Errorf("signature verify failed")
	}
	if payload.TS > time.Now().Add(5*time.Minute).UnixMilli() {
		return friendKeyPayload{}, true, fmt.Errorf("timestamp too far in future")
	}
	if payload.TS < time.Now().Add(-friendKeyMaxAge).UnixMilli() {
		return friendKeyPayload{}, true, fmt.Errorf("timestamp too old")
	}
	payload.E2EEPub = e2eePub
	payload.Nonce = nonce
	return payload, true, nil
}

func (m *model) consumeFriendKey(from string, body string) (string, error) {
	payload, present, err := parseFriendKey(body, from)
	if err != nil {
		return "", err
	}
	if !present {
		return "", nil
	}
	if m.friendKeyNonces[from] == nil {
		m.friendKeyNonces[from] = make(map[string]int64)
	}
	if _, exists := m.friendKeyNonces[from][payload.Nonce]; exists {
		return "", fmt.Errorf("replayed key payload")
	}
	if len(m.friendKeyNonces[from]) > 512 {
		m.friendKeyNonces[from] = make(map[string]int64)
	}
	m.friendKeyNonces[from][payload.Nonce] = payload.TS
	return payload.E2EEPub, nil
}

func (m *model) persistE2EEState() error {
	path := strings.TrimSpace(m.e2eeStatePath)
	if path == "" {
		return nil
	}
	return saveE2EEState(path, m.peerE2EEMulti, m.friendKeyNonces)
}

func addPeerKeyWithLimit(m map[string][]string, loginID string, key string, limit int) bool {
	loginID = strings.TrimSpace(loginID)
	key = strings.TrimSpace(key)
	if loginID == "" || key == "" {
		return false
	}
	keys := m[loginID]
	for i, k := range keys {
		if k == key {
			if i == 0 {
				return false
			}
			copy(keys[1:i+1], keys[0:i])
			keys[0] = key
			m[loginID] = keys
			return true
		}
	}
	keys = append([]string{key}, keys...)
	if limit > 0 && len(keys) > limit {
		keys = keys[:limit]
	}
	m[loginID] = keys
	return true
}

func (m *model) formatE2EEKeys() string {
	ids := m.friendTargets()
	if len(ids) == 0 {
		return "e2ee keys: no friends"
	}
	lines := []string{"e2ee keys:"}
	for _, id := range ids {
		state := "missing"
		if n := len(m.peerE2EEMulti[id]); n > 0 {
			state = fmt.Sprintf("verified(%d)", n)
		} else if issue := strings.TrimSpace(m.e2eeIssues[id]); issue != "" {
			state = "invalid: " + issue
		}
		lines = append(lines, fmt.Sprintf("  %s [%s]", m.displayPeer(id), state))
	}
	return strings.Join(lines, "\n")
}

func (m *model) rotateE2EEKey() (int, error) {
	priv, pubB64, err := netsec.NewX25519Identity()
	if err != nil {
		return 0, err
	}
	payload, err := json.MarshalIndent(e2eeKeyFile{PrivateKey: base64.StdEncoding.EncodeToString(priv.Bytes())}, "", "  ")
	if err != nil {
		return 0, err
	}
	if strings.TrimSpace(m.e2eePath) == "" {
		return 0, fmt.Errorf("missing e2ee key path")
	}
	if err := writeFileAtomic(m.e2eePath, payload, 0o600); err != nil {
		return 0, err
	}
	m.e2ee = priv
	m.e2eeB64 = pubB64
	ids := m.friendTargets()
	shared := 0
	for _, id := range ids {
		if err := m.sendSigned(Packet{Type: "friend_add", To: id, Body: m.friendKeyBody()}); err == nil {
			shared++
		}
	}
	return shared, nil
}

func encodeBodyForSend(body string) (string, string, int, error) {
	if len(body) < compressMinBytes {
		return body, compressionNone, 0, nil
	}
	compressed, err := compressZlib([]byte(body))
	if err != nil {
		return "", "", 0, err
	}
	encoded := base64.StdEncoding.EncodeToString(compressed)
	if len(encoded) >= len(body) {
		return body, compressionNone, 0, nil
	}
	return encoded, compressionZlib, len(body), nil
}

func compressZlib(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		_ = zw.Close()
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodeTextBodyForClient(p Packet) (string, error) {
	comp := strings.ToLower(strings.TrimSpace(p.Compression))
	if comp == "" {
		comp = compressionNone
	}
	switch comp {
	case compressionNone:
		if p.USize > 0 && p.USize != len(p.Body) {
			return "", fmt.Errorf("usize mismatch")
		}
		return p.Body, nil
	case compressionZlib:
		if p.USize <= 0 {
			return "", fmt.Errorf("usize required")
		}
		raw, err := base64.StdEncoding.DecodeString(p.Body)
		if err != nil {
			return "", err
		}
		zr, err := zlib.NewReader(bytes.NewReader(raw))
		if err != nil {
			return "", err
		}
		defer zr.Close()
		decoded, err := io.ReadAll(io.LimitReader(zr, int64(p.USize)+1))
		if err != nil {
			return "", err
		}
		if len(decoded) != p.USize {
			return "", fmt.Errorf("decoded size mismatch")
		}
		return string(decoded), nil
	default:
		return "", fmt.Errorf("unsupported compression")
	}
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
	// Read-merge-write to reduce cross-session clobbering.
	merged := make(map[string]string)
	existing, err := loadContacts(path)
	if err != nil {
		return err
	}
	for a, id := range existing {
		merged[a] = id
	}
	for a, id := range contacts {
		merged[a] = id
	}
	return writeContactsAtomic(path, merged)
}

func writeContactsAtomic(path string, contacts map[string]string) error {
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
	return writeFileAtomic(path, payload, 0o600)
}

func loadUIState(path string) ([]groupEntry, chatContext, error) {
	if strings.TrimSpace(path) == "" {
		return nil, chatContext{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, chatContext{}, nil
		}
		return nil, chatContext{}, err
	}
	var f uiStateFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, chatContext{}, err
	}
	return f.Groups, f.LastContext, nil
}

func saveUIState(path string, groups []groupEntry, ctx chatContext) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	payload, err := json.MarshalIndent(uiStateFile{Groups: groups, LastContext: ctx}, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, payload, 0o600)
}

func loadProfile(path string) (string, string, map[string]string, map[string]string, error) {
	nicks := make(map[string]string)
	peers := make(map[string]string)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", "", nicks, peers, nil
		}
		return "", "", nil, nil, err
	}
	var f profileFile
	if err := json.Unmarshal(data, &f); err != nil {
		return "", "", nil, nil, err
	}
	for _, n := range f.PeerNicknames {
		id := strings.TrimSpace(n.LoginID)
		nick := strings.TrimSpace(n.Nickname)
		if !looksLikeLoginID(id) || nick == "" {
			continue
		}
		nicks[id] = nick
	}
	for _, p := range f.PeerProfiles {
		id := strings.TrimSpace(p.LoginID)
		text := strings.TrimSpace(p.ProfileText)
		if !looksLikeLoginID(id) || text == "" {
			continue
		}
		peers[id] = text
	}
	return strings.TrimSpace(f.DisplayName), strings.TrimSpace(f.ProfileText), nicks, peers, nil
}

func saveProfile(path string, displayName string, profileText string, nicknames map[string]string, peerProfiles map[string]string) error {
	// Read-merge-write to reduce cross-session clobbering.
	existingName, existingText, existingNicks, existingPeers, err := loadProfile(path)
	if err != nil {
		return err
	}
	mergedNicks := make(map[string]string, len(existingNicks)+len(nicknames))
	for id, nick := range existingNicks {
		mergedNicks[id] = nick
	}
	for id, nick := range nicknames {
		mergedNicks[id] = nick
	}
	mergedPeers := make(map[string]string, len(existingPeers)+len(peerProfiles))
	for id, text := range existingPeers {
		mergedPeers[id] = text
	}
	for id, text := range peerProfiles {
		mergedPeers[id] = text
	}
	name := strings.TrimSpace(displayName)
	if name == "" {
		name = strings.TrimSpace(existingName)
	}
	text := strings.TrimSpace(profileText)
	if text == "" {
		text = strings.TrimSpace(existingText)
	}
	return writeProfileAtomic(path, name, text, mergedNicks, mergedPeers)
}

func writeProfileAtomic(path string, displayName string, profileText string, nicknames map[string]string, peerProfiles map[string]string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	ids := make([]string, 0, len(nicknames))
	for id := range nicknames {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	f := profileFile{DisplayName: strings.TrimSpace(displayName), ProfileText: strings.TrimSpace(profileText), PeerNicknames: make([]savedNickname, 0, len(ids))}
	for _, id := range ids {
		nick := strings.TrimSpace(nicknames[id])
		if nick == "" || !looksLikeLoginID(id) {
			continue
		}
		f.PeerNicknames = append(f.PeerNicknames, savedNickname{LoginID: id, Nickname: nick})
	}
	peerIDs := make([]string, 0, len(peerProfiles))
	for id := range peerProfiles {
		peerIDs = append(peerIDs, id)
	}
	sort.Strings(peerIDs)
	f.PeerProfiles = make([]savedProfile, 0, len(peerIDs))
	for _, id := range peerIDs {
		text := strings.TrimSpace(peerProfiles[id])
		if text == "" || !looksLikeLoginID(id) {
			continue
		}
		f.PeerProfiles = append(f.PeerProfiles, savedProfile{LoginID: id, ProfileText: text})
	}
	payload, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, payload, 0o600)
}

func defaultDisplayName() string {
	return fmt.Sprintf("user%06d", time.Now().UnixNano()%1000000)
}

func promptDisplayName(current string) string {
	current = strings.TrimSpace(current)
	if current == "" {
		current = defaultDisplayName()
	}
	fmt.Printf("Choose a display name (optional) [%s]: ", current)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return current
	}
	name := strings.TrimSpace(line)
	if name == "" {
		return current
	}
	return name
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
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
	if err := writeFileAtomic(path, payload, 0o600); err != nil {
		return nil, err
	}
	return priv, nil
}

func e2eePathForKey(home string, keyPath string) string {
	return filepath.Join(home, ".goaccord", "e2ee", "e2ee-"+filepath.Base(strings.TrimSpace(keyPath))+".json")
}

func e2eeStatePathForKey(home string, keyPath string) string {
	return filepath.Join(home, ".goaccord", "e2ee", "e2ee-state-"+filepath.Base(strings.TrimSpace(keyPath))+".json")
}

func loadOrCreateE2EEKey(path string) (*ecdh.PrivateKey, string, error) {
	if data, err := os.ReadFile(path); err == nil {
		var kf e2eeKeyFile
		if err := json.Unmarshal(data, &kf); err != nil {
			return nil, "", err
		}
		priv, pubB64, err := netsec.ParseX25519PrivateKeyB64(kf.PrivateKey)
		if err != nil {
			return nil, "", err
		}
		return priv, pubB64, nil
	}
	priv, pubB64, err := netsec.NewX25519Identity()
	if err != nil {
		return nil, "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, "", err
	}
	payload, err := json.MarshalIndent(e2eeKeyFile{PrivateKey: base64.StdEncoding.EncodeToString(priv.Bytes())}, "", "  ")
	if err != nil {
		return nil, "", err
	}
	if err := writeFileAtomic(path, payload, 0o600); err != nil {
		return nil, "", err
	}
	return priv, pubB64, nil
}

func loadE2EEState(path string) (map[string][]string, map[string]map[string]int64, error) {
	peerKeys := make(map[string][]string)
	nonces := make(map[string]map[string]int64)
	if strings.TrimSpace(path) == "" {
		return peerKeys, nonces, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return peerKeys, nonces, nil
		}
		return nil, nil, err
	}
	var f e2eeStateFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, nil, err
	}
	for _, p := range f.PeerKeys {
		id := strings.TrimSpace(p.LoginID)
		pub := strings.TrimSpace(p.E2EEPub)
		if looksLikeLoginID(id) && pub != "" {
			_ = addPeerKeyWithLimit(peerKeys, id, pub, maxPeerKeysPerLogin)
		}
	}
	for _, n := range f.Nonces {
		id := strings.TrimSpace(n.LoginID)
		nonce := strings.TrimSpace(n.Nonce)
		if !looksLikeLoginID(id) || nonce == "" || n.TS <= 0 {
			continue
		}
		if nonces[id] == nil {
			nonces[id] = make(map[string]int64)
		}
		nonces[id][nonce] = n.TS
	}
	return peerKeys, nonces, nil
}

func saveE2EEState(path string, peerKeys map[string][]string, nonces map[string]map[string]int64) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	ids := make([]string, 0, len(peerKeys))
	for id := range peerKeys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := e2eeStateFile{
		PeerKeys: make([]savedPeerE2EE, 0, len(ids)),
	}
	for _, id := range ids {
		if !looksLikeLoginID(id) {
			continue
		}
		for _, key := range peerKeys[id] {
			pub := strings.TrimSpace(key)
			if pub == "" {
				continue
			}
			out.PeerKeys = append(out.PeerKeys, savedPeerE2EE{LoginID: id, E2EEPub: pub, SeenAt: time.Now().Unix()})
		}
	}
	nonceRows := make([]savedFriendNonce, 0)
	nonceIDs := make([]string, 0, len(nonces))
	for id := range nonces {
		nonceIDs = append(nonceIDs, id)
	}
	sort.Strings(nonceIDs)
	for _, id := range nonceIDs {
		byNonce := nonces[id]
		if !looksLikeLoginID(id) || len(byNonce) == 0 {
			continue
		}
		keys := make([]string, 0, len(byNonce))
		for nonce := range byNonce {
			keys = append(keys, nonce)
		}
		sort.Strings(keys)
		for _, nonce := range keys {
			ts := byNonce[nonce]
			if strings.TrimSpace(nonce) == "" || ts <= 0 {
				continue
			}
			nonceRows = append(nonceRows, savedFriendNonce{LoginID: id, Nonce: nonce, TS: ts})
		}
	}
	out.Nonces = nonceRows
	payload, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, payload, 0o600)
}

func signAction(priv ed25519.PrivateKey, p Packet) (string, error) {
	msg, err := json.Marshal(signedAction{Type: p.Type, ID: p.ID, From: p.From, To: p.To, Body: p.Body, Compression: p.Compression, USize: p.USize, Group: p.Group, Channel: p.Channel, Public: p.Public})
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, msg)
	return base64.StdEncoding.EncodeToString(sig), nil
}

func runAuth(addr string, priv ed25519.PrivateKey) (net.Conn, *json.Encoder, <-chan netMsg, string, string, error) {
	pub := priv.Public().(ed25519.PublicKey)
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	conn, err := tls.Dial("tcp", addr, netsec.ClientTLSConfigInsecure())
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

type identityCandidate struct {
	Path    string
	LoginID string
	Name    string
}

func profilePathForKey(home string, keyPath string) string {
	return filepath.Join(home, ".goaccord", "profiles", "profile-"+filepath.Base(strings.TrimSpace(keyPath))+".json")
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(perm); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func listIdentityCandidates(home string, currentPath string) []identityCandidate {
	seen := make(map[string]struct{})
	paths := make([]string, 0)
	addPath := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		paths = append(paths, p)
	}
	addPath(currentPath)

	legacy := filepath.Join(home, ".goaccord", "ed25519_key.json")
	addPath(legacy)

	idsDir := filepath.Join(home, ".goaccord", "identities")
	if entries, err := os.ReadDir(idsDir); err == nil {
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".json") {
				continue
			}
			addPath(filepath.Join(idsDir, e.Name()))
		}
	}

	out := make([]identityCandidate, 0, len(paths))
	for _, p := range paths {
		priv, err := loadOrCreateKey(p)
		if err != nil {
			continue
		}
		pub := priv.Public().(ed25519.PublicKey)
		name, _, _, _, _ := loadProfile(profilePathForKey(home, p))
		out = append(out, identityCandidate{Path: p, LoginID: loginIDForPubKey(pub), Name: strings.TrimSpace(name)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path == currentPath {
			return true
		}
		if out[j].Path == currentPath {
			return false
		}
		return out[i].Path < out[j].Path
	})
	return out
}

func promptIdentityPath(home string, currentPath string, conflictMode bool) (string, error) {
	candidates := listIdentityCandidates(home, currentPath)
	if conflictMode {
		fmt.Println("login_id already connected on the server.")
		fmt.Println("Choose a different identity:")
	} else {
		fmt.Println("Choose an identity to use:")
	}
	idx := 1
	indexToPath := make(map[int]string)
	for _, c := range candidates {
		if conflictMode && c.Path == currentPath {
			continue
		}
		currentMark := ""
		if c.Path == currentPath {
			currentMark = " [current]"
		}
		label := strings.TrimSpace(c.Name)
		if label == "" {
			label = shortID(c.LoginID)
		}
		fmt.Printf("  %d) %s [%s] (%s)%s\n", idx, label, shortID(c.LoginID), c.Path, currentMark)
		indexToPath[idx] = c.Path
		idx++
	}
	createIdx := idx
	fmt.Printf("  %d) create a new identity\n", createIdx)
	fmt.Println("  q) quit")
	fmt.Print("> ")

	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	choice := strings.TrimSpace(line)
	if strings.EqualFold(choice, "q") {
		return "", fmt.Errorf("aborted by user")
	}
	n, err := strconv.Atoi(choice)
	if err != nil {
		return "", fmt.Errorf("invalid choice")
	}
	if p, ok := indexToPath[n]; ok {
		return p, nil
	}
	if n == createIdx {
		idsDir := filepath.Join(home, ".goaccord", "identities")
		if err := os.MkdirAll(idsDir, 0o700); err != nil {
			return "", err
		}
		path := filepath.Join(idsDir, fmt.Sprintf("id-%d.json", time.Now().UnixNano()))
		if _, err := loadOrCreateKey(path); err != nil {
			return "", err
		}
		return path, nil
	}
	return "", fmt.Errorf("invalid choice")
}

func connectWithIdentitySelection(addr string, home string, initialKeyPath string) (string, ed25519.PrivateKey, net.Conn, *json.Encoder, <-chan netMsg, string, string, error) {
	keyPath := initialKeyPath
	for {
		priv, err := loadOrCreateKey(keyPath)
		if err != nil {
			return "", nil, nil, nil, nil, "", "", fmt.Errorf("key load/create failed: %w", err)
		}
		conn, enc, events, loginID, pubB64, err := runAuth(addr, priv)
		if err == nil {
			return keyPath, priv, conn, enc, events, loginID, pubB64, nil
		}
		if !strings.Contains(err.Error(), "login id already connected") {
			return "", nil, nil, nil, nil, "", "", err
		}
		nextKeyPath, pickErr := promptIdentityPath(home, keyPath, true)
		if pickErr != nil {
			return "", nil, nil, nil, nil, "", "", err
		}
		keyPath = nextKeyPath
	}
}
