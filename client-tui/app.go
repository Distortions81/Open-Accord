package main

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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

type profileFile struct {
	DisplayName   string          `json:"display_name"`
	PeerNicknames []savedNickname `json:"peer_nicknames"`
}

type savedNickname struct {
	LoginID  string `json:"login_id"`
	Nickname string `json:"nickname"`
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

const (
	compressionNone  = "none"
	compressionZlib  = "zlib"
	compressMinBytes = 64
	panelAll         = "all"
	panelDirect      = "direct"
	panelChannel     = "channel"
)

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
	friends      map[string]struct{}
	profilePath  string
	displayName  string
	nicknames    map[string]string

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

func (m *model) addInfoEntry(line string) {
	m.infoEntries = append(m.infoEntries, stamp()+" "+line)
}

func (m *model) addChatEntry(name string, body string, direct string, channel string) {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "unknown"
	}
	body = strings.TrimSpace(body)
	if channel != "" {
		m.chatEntries = append(m.chatEntries, uiEntry{line: fmt.Sprintf("%s %s [%s]: %s", stamp(), name, channel, body), direct: direct, channel: channel})
		return
	}
	m.chatEntries = append(m.chatEntries, uiEntry{line: fmt.Sprintf("%s %s: %s", stamp(), name, body), direct: direct, channel: channel})
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
}

func (m *model) shouldShow(e uiEntry) bool {
	switch m.focusMode {
	case panelDirect:
		return e.direct == m.focusDirect
	case panelChannel:
		return e.channel == m.focusChannel
	default:
		return true
	}
}

func (m *model) commandNames() []string {
	return []string{
		"/help", "/to", "/use", "/contacts", "/remove-contact", "/friends",
		"/nick", "/myname",
		"/chat", "/chat-channel", "/panels", "/focus",
		"/group", "/channel", "/clearctx", "/whoami",
		"/friend-add", "/friend-accept",
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
		"/to": {}, "/use": {}, "/chat": {}, "/friend-add": {}, "/friend-accept": {}, "/invite": {},
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
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			_ = m.conn.Close()
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
				_ = m.conn.Close()
				return m, tea.Quit
			}
			if strings.HasPrefix(line, "/") {
				cmd := (&m).handleCommand(line)
				return m, cmd
			}

			directCtx := ""
			channelCtx := ""
			if strings.TrimSpace(m.group) != "" || strings.TrimSpace(m.channel) != "" {
				if strings.TrimSpace(m.group) == "" || strings.TrimSpace(m.channel) == "" {
					return m, logLine("set both /group and /channel, or use /chat for direct messages")
				}
				if err := m.sendSigned(Packet{Type: "channel_send", Group: m.group, Channel: m.channel, Body: line}); err != nil {
					return m, tea.Batch(logLine("send error: "+err.Error()), tea.Quit)
				}
				channelCtx = m.group + "/" + m.channel
				m.addChatEntry(m.displayName, line, directCtx, channelCtx)
				return m, nil
			}

			if strings.TrimSpace(m.to) == "" {
				return m, logLine("set recipient with /to <login_id|alias> or /chat <login_id|alias>")
			}
			if err := m.sendSigned(Packet{Type: "send", To: m.to, Body: line}); err != nil {
				return m, tea.Batch(logLine("send error: "+err.Error()), tea.Quit)
			}
			directCtx = m.to
			m.addChatEntry(m.displayName, line, directCtx, "")
			return m, nil
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

		directCtx := ""
		channelCtx := ""
		if strings.TrimSpace(msg.pkt.Group) != "" && strings.TrimSpace(msg.pkt.Channel) != "" {
			channelCtx = msg.pkt.Group + "/" + msg.pkt.Channel
		}

		switch msg.pkt.Type {
		case "deliver", "channel_deliver":
			line := msg.pkt.Body
			if msg.pkt.Origin != "" {
				line += " (via " + msg.pkt.Origin + ")"
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
		case "friend_request", "friend_update", "channel_invite", "channel_update", "channel_joined":
			if msg.pkt.Type == "friend_update" {
				other := msg.pkt.From
				if other == m.loginID {
					other = msg.pkt.To
				}
				if looksLikeLoginID(other) && other != m.loginID {
					m.friends[other] = struct{}{}
				}
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
		statusStyle.Render("panel="+panelLabel+" login="+m.displayPeer(m.loginID)+" to="+emptyDash(m.displayPeer(m.to))+" group="+emptyDash(m.group)+" channel="+emptyDash(m.channel)+fmt.Sprintf(" contacts=%d friends=%d", len(m.contacts), len(m.friends)))

	visible := make([]string, 0, len(m.chatEntries))
	for _, e := range m.chatEntries {
		if m.shouldShow(e) {
			visible = append(visible, e.line)
		}
	}

	maxLines := m.height - 6
	if maxLines < 4 {
		maxLines = 4
	}
	start := 0
	if len(visible) > maxLines {
		start = len(visible) - maxLines
	}
	body := strings.Join(visible[start:], "\n")
	if body == "" {
		body = "No messages in this panel. /panels and /focus to switch."
	}

	infoLines := m.height / 5
	if infoLines < 4 {
		infoLines = 4
	}
	maxInfo := infoLines - 2
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
	infoPanel := infoBoxStyle.Width(maxInt(20, m.width-2)).Render(infoBody)

	chatPanel := chatBoxStyle.Width(maxInt(20, m.width-2)).Render(body)

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
		lines = append(lines, fmt.Sprintf("  %s (%s)", m.displayPeer(id), id))
	}
	return strings.Join(lines, "\n")
}

func (m *model) handleCommand(line string) tea.Cmd {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return nil
	}
	switch parts[0] {
	case "/help":
		return logLine("commands: /to /use /chat /chat-channel /panels /focus /contacts /friends /remove-contact /nick /myname /group /channel /clearctx /whoami /friend-add /friend-accept /channel-create /invite /channel-join /channel-leave /channel-send /quit")
	case "/to", "/use", "/chat":
		if len(parts) < 2 {
			return logLine("usage: " + parts[0] + " <login_id|alias>")
		}
		target, ok := m.resolveRecipient(parts[1])
		if !ok {
			return logLine("unknown alias/login_id: " + strings.TrimSpace(parts[1]))
		}
		m.to = target
		m.group = ""
		m.channel = ""
		m.applyFocus(panelTarget{mode: panelDirect, direct: target})
		return logLine("chat target set: " + m.displayPeer(m.to))
	case "/chat-channel":
		if len(parts) < 3 {
			return logLine("usage: /chat-channel <group> <channel>")
		}
		m.group = strings.TrimSpace(parts[1])
		m.channel = strings.TrimSpace(parts[2])
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
		if err := m.sendSigned(Packet{Type: "friend_add", To: target}); err != nil {
			return logLine("friend-add error: " + err.Error())
		}
		return logLine("friend request sent to " + m.displayPeer(target))
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
		return logLine("friend accepted: " + m.displayPeer(target))
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
		if err := m.sendSigned(Packet{Type: "channel_invite", To: target, Group: m.group, Channel: m.channel}); err != nil {
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
		m.addChatEntry(m.displayName, text, "", m.group+"/"+m.channel)
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
	return saveProfile(m.profilePath, m.displayName, m.nicknames)
}

func (m *model) setDisplayName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("display name required")
	}
	m.displayName = name
	return saveProfile(m.profilePath, m.displayName, m.nicknames)
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
	return writeFileAtomic(path, payload, 0o600)
}

func loadProfile(path string) (string, map[string]string, error) {
	nicks := make(map[string]string)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nicks, nil
		}
		return "", nil, err
	}
	var f profileFile
	if err := json.Unmarshal(data, &f); err != nil {
		return "", nil, err
	}
	for _, n := range f.PeerNicknames {
		id := strings.TrimSpace(n.LoginID)
		nick := strings.TrimSpace(n.Nickname)
		if !looksLikeLoginID(id) || nick == "" {
			continue
		}
		nicks[id] = nick
	}
	return strings.TrimSpace(f.DisplayName), nicks, nil
}

func saveProfile(path string, displayName string, nicknames map[string]string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	ids := make([]string, 0, len(nicknames))
	for id := range nicknames {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	f := profileFile{DisplayName: strings.TrimSpace(displayName), PeerNicknames: make([]savedNickname, 0, len(ids))}
	for _, id := range ids {
		nick := strings.TrimSpace(nicknames[id])
		if nick == "" || !looksLikeLoginID(id) {
			continue
		}
		f.PeerNicknames = append(f.PeerNicknames, savedNickname{LoginID: id, Nickname: nick})
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

type identityCandidate struct {
	Path    string
	LoginID string
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
		out = append(out, identityCandidate{Path: p, LoginID: loginIDForPubKey(pub)})
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

func promptIdentityPath(home string, currentPath string) (string, error) {
	candidates := listIdentityCandidates(home, currentPath)
	fmt.Println("login_id already connected on the server.")
	fmt.Println("Choose an identity to use:")
	idx := 1
	indexToPath := make(map[int]string)
	for _, c := range candidates {
		if c.Path == currentPath {
			continue
		}
		fmt.Printf("  %d) switch to %s (%s)\n", idx, shortID(c.LoginID), c.Path)
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
		nextKeyPath, pickErr := promptIdentityPath(home, keyPath)
		if pickErr != nil {
			return "", nil, nil, nil, nil, "", "", err
		}
		keyPath = nextKeyPath
	}
}
