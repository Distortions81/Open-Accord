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
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"goaccord/internal/netsec"
)

type Packet struct {
	Type        string   `json:"type"`
	Role        string   `json:"role,omitempty"`
	ID          string   `json:"id,omitempty"`
	From        string   `json:"from,omitempty"`
	To          string   `json:"to,omitempty"`
	Body        string   `json:"body,omitempty"`
	Compression string   `json:"compression,omitempty"`
	USize       int      `json:"usize,omitempty"`
	Group       string   `json:"group,omitempty"`
	Channel     string   `json:"channel,omitempty"`
	Public      bool     `json:"public,omitempty"`
	Origin      string   `json:"origin,omitempty"`
	Nonce       string   `json:"nonce,omitempty"`
	PubKey      string   `json:"pub_key,omitempty"`
	Sig         string   `json:"sig,omitempty"`
	CreatedAt   int64    `json:"created_at,omitempty"`
	Hops        []hopRef `json:"hops,omitempty"`
}

type hopRef struct {
	Node string `json:"node"`
	TS   int64  `json:"ts"`
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
	CreatedAt   int64  `json:"created_at,omitempty"`
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

type uiStateFile struct {
	Groups      []groupEntry `json:"groups,omitempty"`
	LastContext chatContext  `json:"last_context,omitempty"`
}

type savedNickname struct {
	LoginID  string `json:"login_id"`
	Nickname string `json:"nickname"`
}

type savedProfile struct {
	LoginID     string `json:"login_id"`
	ProfileText string `json:"profile_text"`
	RefreshedAt int64  `json:"refreshed_at,omitempty"`
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

type identityCandidate struct {
	Path    string
	LoginID string
	Name    string
}

func profilePathForKey(home string, keyPath string) string {
	return filepath.Join(home, ".goaccord", "profiles", "profile-"+filepath.Base(strings.TrimSpace(keyPath))+".json")
}

func uiStatePathForProfile(profilePath string) string {
	return strings.TrimSpace(profilePath) + ".ui.json"
}

type webEvent struct {
	Seq        int64  `json:"seq"`
	Kind       string `json:"kind"`
	Text       string `json:"text"`
	TS         string `json:"ts"`
	ActorID    string `json:"actor_id,omitempty"`
	ActorLabel string `json:"actor_label,omitempty"`
	Mode       string `json:"mode,omitempty"`    // dm|group
	Target     string `json:"target,omitempty"`  // dm target
	Group      string `json:"group,omitempty"`   // group context
	Channel    string `json:"channel,omitempty"` // channel context
	InviteKey  string `json:"invite_key,omitempty"`
}

type dmTarget struct {
	ID            string `json:"id"`
	Label         string `json:"label"`
	Nickname      string `json:"nickname,omitempty"`
	ProfileText   string `json:"profile_text,omitempty"`
	LastRefreshed int64  `json:"last_refreshed,omitempty"`
	Online        string `json:"online,omitempty"`
	OnlineTTLSec  int    `json:"online_ttl_sec,omitempty"`
	E2EEReady     bool   `json:"e2ee_ready"`
	E2EEStatus    string `json:"e2ee_status,omitempty"`
}

type channelInviteEntry struct {
	FromID     string `json:"from_id"`
	FromLabel  string `json:"from_label"`
	Group      string `json:"group"`
	Channel    string `json:"channel"`
	ReceivedAt int64  `json:"received_at"`
	InviteKey  string `json:"invite_key"`
}

type groupEntry struct {
	Name       string   `json:"name"`
	Channels   []string `json:"channels,omitempty"`
	Owned      bool     `json:"owned,omitempty"`
	OwnerID    string   `json:"owner_id,omitempty"`
	OwnerLabel string   `json:"owner_label,omitempty"`
}

type webClient struct {
	mu sync.Mutex

	enc     *json.Encoder
	conn    net.Conn
	priv    ed25519.PrivateKey
	pubB64  string
	e2ee    *ecdh.PrivateKey
	e2eeB64 string

	loginID       string
	displayName   string
	profileText   string
	contactsPath  string
	profilePath   string
	uiStatePath   string
	e2eePath      string
	e2eeStatePath string

	contacts         map[string]string
	nicknames        map[string]string
	peerProfiles     map[string]string
	profileRefreshed map[string]int64
	presence         map[string]string
	presenceTTL      map[string]int
	presenceVisible  bool
	presenceTTLSec   int
	friends          map[string]struct{}
	pendingFriends   map[string]int64
	pendingInvites   map[string]channelInviteEntry
	groups           map[string]map[string]struct{}
	ownedGroups      map[string]struct{}
	groupOwners      map[string]string
	lastContext      chatContext
	pendingPings     map[string]int64
	seenChatIDs      map[string]struct{}
	peerE2EEMulti    map[string][]string
	friendKeyNonces  map[string]map[string]int64
	e2eeIssues       map[string]string

	events  []webEvent
	nextSeq int64

	counter atomic.Uint64

	serverAddr   string
	reconnecting bool
}

const (
	compressionNone  = "none"
	compressionZlib  = "zlib"
	compressMinBytes = 64

	presenceKeepaliveInterval = 5 * time.Minute
	minPresenceTTLSec         = 180
	maxPresenceTTLSec         = 900
	defaultPresenceTTLSec     = 390
	friendKeyMaxAge           = 30 * 24 * time.Hour
	maxPeerKeysPerLogin       = 8
)

func stamp() string { return time.Now().Format("15:04:05") }

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (c *webClient) addEvent(kind string, text string) {
	c.addEventWithActor(kind, text, "")
}

func (c *webClient) addEventWithActor(kind string, text string, actorID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nextSeq++
	actorLabel := ""
	if strings.TrimSpace(actorID) != "" {
		actorLabel = c.displayPeerLocked(actorID)
	}
	c.events = append(c.events, webEvent{Seq: c.nextSeq, Kind: kind, Text: text, TS: stamp(), ActorID: strings.TrimSpace(actorID), ActorLabel: actorLabel})
	if len(c.events) > 1000 {
		c.events = c.events[len(c.events)-1000:]
	}
}

func (c *webClient) addChatEventWithActor(text string, actorID string, mode string, target string, group string, channel string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nextSeq++
	actorLabel := ""
	if strings.TrimSpace(actorID) != "" {
		actorLabel = c.displayPeerLocked(actorID)
	}
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != "dm" && mode != "group" {
		mode = ""
	}
	e := webEvent{
		Seq:        c.nextSeq,
		Kind:       "chat",
		Text:       text,
		TS:         stamp(),
		ActorID:    strings.TrimSpace(actorID),
		ActorLabel: actorLabel,
		Mode:       mode,
		Target:     strings.TrimSpace(target),
		Group:      strings.TrimSpace(group),
		Channel:    strings.TrimSpace(channel),
	}
	if e.Mode == "group" && e.Channel == "" {
		e.Channel = "default"
	}
	c.events = append(c.events, e)
	if len(c.events) > 1000 {
		c.events = c.events[len(c.events)-1000:]
	}
}

func (c *webClient) addInviteChatEvent(text string, actorID string, target string, inviteKey string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nextSeq++
	actorID = strings.TrimSpace(actorID)
	e := webEvent{
		Seq:        c.nextSeq,
		Kind:       "chat",
		Text:       text,
		TS:         stamp(),
		ActorID:    actorID,
		ActorLabel: c.displayPeerLocked(actorID),
		Mode:       "dm",
		Target:     strings.TrimSpace(target),
		InviteKey:  strings.TrimSpace(inviteKey),
	}
	c.events = append(c.events, e)
	if len(c.events) > 1000 {
		c.events = c.events[len(c.events)-1000:]
	}
}

func (c *webClient) displayPeer(loginID string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.displayPeerLocked(loginID)
}

func (c *webClient) displayPeerLocked(loginID string) string {
	loginID = strings.TrimSpace(loginID)
	if loginID == "" {
		return "-"
	}
	if loginID == c.loginID && strings.TrimSpace(c.displayName) != "" {
		return c.displayName
	}
	if nick, ok := c.nicknames[loginID]; ok && strings.TrimSpace(nick) != "" {
		return nick
	}
	for alias, id := range c.contacts {
		if id == loginID {
			return alias
		}
	}
	return shortID(loginID)
}

func (c *webClient) resolveRecipient(token string) (string, bool) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, nick := range c.nicknames {
		if strings.EqualFold(strings.TrimSpace(nick), token) && looksLikeLoginID(id) {
			return id, true
		}
	}
	if id, ok := c.contacts[token]; ok {
		return id, true
	}
	if looksLikeLoginID(token) {
		return token, true
	}
	return "", false
}

func (c *webClient) nextMessageID() string {
	n := c.counter.Add(1)
	prefix := c.loginID
	if len(prefix) > 12 {
		prefix = prefix[:12]
	}
	return fmt.Sprintf("%s-%d-%d", prefix, time.Now().UnixNano(), n)
}

func (c *webClient) sendSignedWithID(p Packet) (string, error) {
	p.ID = c.nextMessageID()
	p.From = c.loginID
	p.PubKey = c.pubB64
	if p.CreatedAt <= 0 {
		p.CreatedAt = time.Now().UnixMilli()
	}
	if strings.TrimSpace(p.Body) != "" {
		body, comp, usize, err := encodeBodyForSend(p.Body)
		if err != nil {
			return "", err
		}
		p.Body = body
		p.Compression = comp
		p.USize = usize
	}
	sig, err := signAction(c.priv, p)
	if err != nil {
		return "", err
	}
	p.Sig = sig
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.enc.Encode(p); err != nil {
		return "", err
	}
	return p.ID, nil
}

func (c *webClient) sendSigned(p Packet) error {
	_, err := c.sendSignedWithID(p)
	return err
}

func (c *webClient) requestProfile(target string) {
	target = strings.TrimSpace(target)
	if !looksLikeLoginID(target) || target == c.loginID {
		return
	}
	_ = c.sendSigned(Packet{Type: "profile_get", To: target})
}

func (c *webClient) requestPresence(target string) {
	target = strings.TrimSpace(target)
	if !looksLikeLoginID(target) || target == c.loginID {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.enc.Encode(Packet{Type: "presence_get", To: target})
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

func (c *webClient) sendPresenceKeepalive() error {
	c.mu.Lock()
	visible := c.presenceVisible
	ttl := normalizePresenceTTLSec(c.presenceTTLSec)
	c.presenceTTLSec = ttl
	c.mu.Unlock()
	b, err := json.Marshal(presenceKeepalivePayload{Visible: visible, TTLSec: ttl})
	if err != nil {
		return err
	}
	return c.sendSigned(Packet{Type: "presence_keepalive", Body: string(b)})
}

func (c *webClient) setOwnPresenceConfig(visible bool, ttlSec int) error {
	ttlSec = normalizePresenceTTLSec(ttlSec)
	c.mu.Lock()
	c.presenceVisible = visible
	c.presenceTTLSec = ttlSec
	c.mu.Unlock()
	return c.sendPresenceKeepalive()
}

func (c *webClient) setPresence(loginID string, state string, ttl int) {
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
	c.mu.Lock()
	c.presence[loginID] = state
	if ttl > 0 {
		c.presenceTTL[loginID] = normalizePresenceTTLSec(ttl)
	}
	c.mu.Unlock()
}

func (c *webClient) publishOwnProfile() error {
	c.mu.Lock()
	payload := profilePayload{Nickname: c.displayName, ProfileText: c.profileText}
	c.mu.Unlock()
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return c.sendSigned(Packet{Type: "profile_set", Body: string(b)})
}

func (c *webClient) encryptDirectMessage(target string, plaintext string) (string, error) {
	c.mu.Lock()
	recipientPubs := append([]string(nil), c.peerE2EEMulti[target]...)
	e2eePriv := c.e2ee
	c.mu.Unlock()
	if len(recipientPubs) == 0 {
		return "", fmt.Errorf("missing verified recipient e2ee key; complete friend handshake")
	}
	return netsec.EncryptDMMulti(e2eePriv, recipientPubs, plaintext)
}

func (c *webClient) friendKeyBody() string {
	c.mu.Lock()
	pub := strings.TrimSpace(c.e2eeB64)
	signingPub := strings.TrimSpace(c.pubB64)
	signingPriv := c.priv
	c.mu.Unlock()
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

func (c *webClient) consumeFriendKey(from string, body string) (string, error) {
	payload, present, err := parseFriendKey(body, from)
	if err != nil {
		return "", err
	}
	if !present {
		return "", nil
	}
	c.mu.Lock()
	if c.friendKeyNonces[from] == nil {
		c.friendKeyNonces[from] = make(map[string]int64)
	}
	if _, exists := c.friendKeyNonces[from][payload.Nonce]; exists {
		c.mu.Unlock()
		return "", fmt.Errorf("replayed key payload")
	}
	if len(c.friendKeyNonces[from]) > 512 {
		c.friendKeyNonces[from] = make(map[string]int64)
	}
	c.friendKeyNonces[from][payload.Nonce] = payload.TS
	c.mu.Unlock()
	return payload.E2EEPub, nil
}

func (c *webClient) persistE2EEState() error {
	c.mu.Lock()
	path := strings.TrimSpace(c.e2eeStatePath)
	peer := cloneMultiStringMap(c.peerE2EEMulti)
	nonces := cloneNonceMap(c.friendKeyNonces)
	c.mu.Unlock()
	if path == "" {
		return nil
	}
	return saveE2EEState(path, peer, nonces)
}

func cloneMultiStringMap(m map[string][]string) map[string][]string {
	out := make(map[string][]string, len(m))
	for k, v := range m {
		cp := make([]string, 0, len(v))
		for _, s := range v {
			s = strings.TrimSpace(s)
			if s != "" {
				cp = append(cp, s)
			}
		}
		out[k] = cp
	}
	return out
}

func addPeerKeyWithLimit(m map[string][]string, loginID string, key string, limit int) bool {
	loginID = strings.TrimSpace(loginID)
	key = strings.TrimSpace(key)
	if loginID == "" || key == "" {
		return false
	}
	keys := m[loginID]
	// Move existing key to the front.
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

func (c *webClient) upsertNickname(loginID, nick string) {
	loginID = strings.TrimSpace(loginID)
	nick = strings.TrimSpace(nick)
	if !looksLikeLoginID(loginID) || nick == "" {
		return
	}
	c.mu.Lock()
	c.nicknames[loginID] = nick
	displayName := c.displayName
	profileText := c.profileText
	nickCopy := cloneStringMap(c.nicknames)
	peerCopy := cloneStringMap(c.peerProfiles)
	refCopy := cloneInt64Map(c.profileRefreshed)
	c.mu.Unlock()
	_ = saveProfile(c.profilePath, displayName, profileText, nickCopy, peerCopy, refCopy)
}

func (c *webClient) upsertPeerProfile(loginID, text string) {
	loginID = strings.TrimSpace(loginID)
	text = strings.TrimSpace(text)
	if !looksLikeLoginID(loginID) || text == "" {
		return
	}
	c.mu.Lock()
	c.peerProfiles[loginID] = text
	c.profileRefreshed[loginID] = time.Now().Unix()
	displayName := c.displayName
	profileText := c.profileText
	nickCopy := cloneStringMap(c.nicknames)
	peerCopy := cloneStringMap(c.peerProfiles)
	refCopy := cloneInt64Map(c.profileRefreshed)
	c.mu.Unlock()
	_ = saveProfile(c.profilePath, displayName, profileText, nickCopy, peerCopy, refCopy)
}

func (c *webClient) rememberGroup(group string, channel string) {
	group = strings.TrimSpace(group)
	channel = strings.TrimSpace(channel)
	if group == "" {
		return
	}
	c.mu.Lock()
	if c.groups[group] == nil {
		c.groups[group] = make(map[string]struct{})
	}
	if channel != "" {
		c.groups[group][channel] = struct{}{}
	}
	c.mu.Unlock()
	c.persistUIState()
}

func (c *webClient) forgetGroup(group string) {
	group = strings.TrimSpace(group)
	if group == "" {
		return
	}
	c.mu.Lock()
	delete(c.groups, group)
	delete(c.ownedGroups, group)
	delete(c.groupOwners, group)
	c.mu.Unlock()
	c.persistUIState()
}

func messageMeta(p Packet) string {
	parts := make([]string, 0, 3)
	if p.CreatedAt > 0 {
		age := time.Now().UnixMilli() - p.CreatedAt
		if age >= 0 {
			parts = append(parts, fmt.Sprintf("age=%dms", age))
		}
	}
	if len(p.Hops) > 0 {
		nodes := make([]string, 0, len(p.Hops))
		for _, h := range p.Hops {
			node := strings.TrimSpace(h.Node)
			if node == "" {
				continue
			}
			if i := strings.LastIndex(node, ":"); i >= 0 && i+1 < len(node) {
				node = node[i+1:]
			}
			nodes = append(nodes, node)
		}
		if len(nodes) > 0 {
			parts = append(parts, fmt.Sprintf("hops=%d(%s)", len(nodes), strings.Join(nodes, "->")))
		} else {
			parts = append(parts, fmt.Sprintf("hops=%d", len(p.Hops)))
		}
	}
	return strings.Join(parts, " ")
}

func (c *webClient) networkLoop(ch <-chan netMsg) {
	for ev := range ch {
		if ev.err != nil {
			c.handleDisconnect(ev.err)
			return
		}
		p := ev.pkt
		switch p.Type {
		case "deliver", "channel_deliver":
			msgID := strings.TrimSpace(p.ID)
			if msgID != "" {
				c.mu.Lock()
				if _, exists := c.seenChatIDs[msgID]; exists {
					c.mu.Unlock()
					continue
				}
				c.seenChatIDs[msgID] = struct{}{}
				if len(c.seenChatIDs) > 5000 {
					c.seenChatIDs = make(map[string]struct{})
				}
				c.mu.Unlock()
			}
			if looksLikeLoginID(p.From) {
				c.setPresence(p.From, "online", defaultPresenceTTLSec)
			}
			line := p.Body
			if p.Type == "deliver" && strings.TrimSpace(p.Group) == "" && strings.TrimSpace(p.Channel) == "" && strings.TrimSpace(p.From) != c.loginID {
				decodedDM, err := netsec.DecryptDM(c.e2ee, p.Body)
				if err != nil {
					c.addEvent("info", "dm decrypt failed from "+c.displayPeer(p.From)+": "+err.Error())
					continue
				} else {
					line = decodedDM
				}
			}
			if strings.TrimSpace(p.Group) != "" && strings.TrimSpace(p.Channel) != "" {
				c.rememberGroup(p.Group, p.Channel)
				c.addChatEventWithActor(line, p.From, "group", "", p.Group, p.Channel)
			} else {
				target := strings.TrimSpace(p.From)
				if strings.TrimSpace(p.From) == c.loginID {
					target = strings.TrimSpace(p.To)
				}
				c.addChatEventWithActor(line, p.From, "dm", target, "", "")
			}
			if meta := messageMeta(p); meta != "" {
				c.addEvent("info", fmt.Sprintf("msg from=%s %s", c.displayPeer(p.From), meta))
			}
			if p.Origin != "" {
				c.addEvent("info", "message via "+p.Origin)
			}
		case "ping":
			if looksLikeLoginID(p.From) {
				c.setPresence(p.From, "online", defaultPresenceTTLSec)
			}
			if meta := messageMeta(p); meta != "" {
				c.addEvent("info", fmt.Sprintf("ping from=%s %s", c.displayPeer(p.From), meta))
			} else {
				c.addEvent("info", fmt.Sprintf("ping from=%s", c.displayPeer(p.From)))
			}
			replyBody, _ := json.Marshal(map[string]any{"ping_id": p.ID, "ping_created_at": p.CreatedAt})
			_ = c.sendSigned(Packet{Type: "pong", To: p.From, Body: string(replyBody)})
		case "pong":
			if looksLikeLoginID(p.From) {
				c.setPresence(p.From, "online", defaultPresenceTTLSec)
			}
			var payload struct {
				PingID        string `json:"ping_id"`
				PingCreatedAt int64  `json:"ping_created_at"`
			}
			_ = json.Unmarshal([]byte(strings.TrimSpace(p.Body)), &payload)
			rtt := int64(0)
			if strings.TrimSpace(payload.PingID) != "" {
				c.mu.Lock()
				if sent, ok := c.pendingPings[payload.PingID]; ok {
					rtt = time.Now().UnixMilli() - sent
					delete(c.pendingPings, payload.PingID)
				}
				c.mu.Unlock()
			}
			meta := messageMeta(p)
			if rtt > 0 {
				if meta != "" {
					meta += " "
				}
				meta += fmt.Sprintf("rtt=%dms", rtt)
			}
			if meta != "" {
				c.addEvent("info", fmt.Sprintf("pong from=%s %s", c.displayPeer(p.From), meta))
			} else {
				c.addEvent("info", fmt.Sprintf("pong from=%s", c.displayPeer(p.From)))
			}
		case "friend_request":
			if p.To == c.loginID && looksLikeLoginID(p.From) {
				c.setPresence(p.From, "online", defaultPresenceTTLSec)
				c.mu.Lock()
				c.pendingFriends[p.From] = time.Now().Unix()
				c.mu.Unlock()
				if k, err := c.consumeFriendKey(p.From, p.Body); err != nil {
					c.mu.Lock()
					c.e2eeIssues[p.From] = err.Error()
					c.mu.Unlock()
					c.addEvent("info", "friend key rejected from "+c.displayPeer(p.From)+": "+err.Error())
				} else if k != "" {
					c.mu.Lock()
					_ = addPeerKeyWithLimit(c.peerE2EEMulti, p.From, k, maxPeerKeysPerLogin)
					delete(c.e2eeIssues, p.From)
					c.mu.Unlock()
					if err := c.persistE2EEState(); err != nil {
						c.addEvent("info", "e2ee state persist failed: "+err.Error())
					}
				}
				c.requestProfile(p.From)
			}
			c.addEvent("info", fmt.Sprintf("friend request from %s", c.displayPeer(p.From)))
		case "friend_update", "group_invite", "channel_update", "channel_joined", "group_invite_rejected":
			if looksLikeLoginID(p.From) {
				c.setPresence(p.From, "online", defaultPresenceTTLSec)
			}
			if strings.TrimSpace(p.Group) != "" {
				if p.Type != "group_invite" {
					c.rememberGroup(p.Group, p.Channel)
				}
				if looksLikeLoginID(p.From) {
					c.mu.Lock()
					if _, ok := c.groupOwners[strings.TrimSpace(p.Group)]; !ok || p.Type == "channel_update" {
						c.groupOwners[strings.TrimSpace(p.Group)] = strings.TrimSpace(p.From)
					}
					c.mu.Unlock()
				}
			}
			if p.Type == "group_invite" && p.To == c.loginID && strings.TrimSpace(p.Group) != "" {
				group := strings.TrimSpace(p.Group)
				from := strings.TrimSpace(p.From)
				channels := make([]string, 0)
				if strings.TrimSpace(p.Body) != "" {
					var payload struct {
						Channels []string `json:"channels"`
					}
					if err := json.Unmarshal([]byte(strings.TrimSpace(p.Body)), &payload); err == nil {
						for _, ch := range payload.Channels {
							ch = strings.TrimSpace(ch)
							if ch == "" {
								continue
							}
							channels = append(channels, ch)
						}
					}
				}
				c.mu.Lock()
				if looksLikeLoginID(from) && from != c.loginID {
					c.contacts[shortID(from)] = from
				}
				key := channelInviteKey(from, group)
				c.pendingInvites[key] = channelInviteEntry{
					FromID:     from,
					Group:      group,
					Channel:    "",
					ReceivedAt: time.Now().Unix(),
				}
				contacts := cloneStringMap(c.contacts)
				c.mu.Unlock()
				_ = saveContacts(c.contactsPath, contacts)
				msg := fmt.Sprintf("invited you to group %s", group)
				if len(channels) > 0 {
					msg += " channels: " + strings.Join(channels, ", ")
				}
				c.addInviteChatEvent(msg, p.From, strings.TrimSpace(p.From), key)
			}
			if p.Type == "channel_joined" && p.To == c.loginID && strings.TrimSpace(p.Group) != "" {
				group := strings.TrimSpace(p.Group)
				c.mu.Lock()
				for key, inv := range c.pendingInvites {
					if normalizeGroupName(inv.Group) == group {
						delete(c.pendingInvites, key)
					}
				}
				c.mu.Unlock()
			}
			if p.Type == "group_invite_rejected" && p.To == c.loginID && strings.TrimSpace(p.Group) != "" {
				group := strings.TrimSpace(p.Group)
				c.addEvent("info", fmt.Sprintf("group invite rejected by %s for %s", c.displayPeer(p.From), group))
			}
			if p.Type == "channel_update" && p.From == c.loginID {
				body := strings.ToLower(strings.TrimSpace(p.Body))
				if body == "created" {
					c.mu.Lock()
					c.ownedGroups[strings.TrimSpace(p.Group)] = struct{}{}
					c.mu.Unlock()
					c.persistUIState()
				}
			}
			if p.Type == "friend_update" {
				if looksLikeLoginID(p.From) {
					if k, err := c.consumeFriendKey(p.From, p.Body); err != nil {
						c.mu.Lock()
						c.e2eeIssues[p.From] = err.Error()
						c.mu.Unlock()
						c.addEvent("info", "friend key rejected from "+c.displayPeer(p.From)+": "+err.Error())
					} else if k != "" {
						c.mu.Lock()
						_ = addPeerKeyWithLimit(c.peerE2EEMulti, p.From, k, maxPeerKeysPerLogin)
						delete(c.e2eeIssues, p.From)
						c.mu.Unlock()
						if err := c.persistE2EEState(); err != nil {
							c.addEvent("info", "e2ee state persist failed: "+err.Error())
						}
					}
				}
				other := p.From
				if other == c.loginID {
					other = p.To
				}
				if looksLikeLoginID(other) && other != c.loginID {
					c.mu.Lock()
					c.friends[other] = struct{}{}
					delete(c.pendingFriends, other)
					c.mu.Unlock()
				}
			}
			c.addEvent("info", fmt.Sprintf("[%s] from=%s to=%s %s", p.Type, c.displayPeer(p.From), c.displayPeer(p.To), strings.TrimSpace(p.Body)))
		case "profile_data":
			if looksLikeLoginID(p.From) {
				c.setPresence(p.From, "online", defaultPresenceTTLSec)
			}
			decoded, err := decodeTextBodyForClient(p)
			if err != nil {
				c.addEvent("info", "profile decode failed: "+err.Error())
				continue
			}
			var prof profilePayload
			if err := json.Unmarshal([]byte(decoded), &prof); err != nil {
				c.addEvent("info", "profile parse failed")
				continue
			}
			nick := strings.TrimSpace(prof.Nickname)
			if nick != "" {
				c.upsertNickname(p.From, nick)
			}
			text := strings.TrimSpace(prof.ProfileText)
			if text != "" {
				c.upsertPeerProfile(p.From, text)
			}
			line := "profile " + c.displayPeer(p.From)
			if nick != "" {
				line += " nick=" + nick
			}
			if text != "" {
				line += " bio=" + text
			}
			c.addEvent("info", line)
		case "presence_data":
			var pd presenceDataPayload
			if err := json.Unmarshal([]byte(strings.TrimSpace(p.Body)), &pd); err == nil {
				c.setPresence(p.From, pd.State, pd.TTLSec)
			} else {
				c.setPresence(p.From, p.Body, 0)
			}
		case "error":
			c.addEvent("info", "server error: "+p.Body)
		default:
			raw, _ := json.Marshal(p)
			c.addEvent("info", "server: "+string(raw))
		}
	}
}

func (c *webClient) handleDisconnect(err error) {
	if errors.Is(err, io.EOF) {
		c.addEvent("info", "connection closed; reconnecting...")
	} else {
		c.addEvent("info", "network error: "+err.Error()+"; reconnecting...")
	}
	c.mu.Lock()
	if c.reconnecting {
		c.mu.Unlock()
		return
	}
	c.reconnecting = true
	c.mu.Unlock()
	go c.reconnectLoop()
}

func (c *webClient) reconnectLoop() {
	attempt := 0
	for {
		if attempt > 0 {
			backoff := time.Second * time.Duration(1<<minInt(attempt, 5))
			time.Sleep(backoff)
		}
		conn, enc, events, loginID, pubB64, err := runAuth(c.serverAddr, c.priv)
		if err != nil {
			attempt++
			c.addEvent("info", fmt.Sprintf("reconnect failed (attempt %d): %v", attempt, err))
			continue
		}
		if strings.TrimSpace(loginID) != c.loginID {
			_ = conn.Close()
			attempt++
			c.addEvent("info", "reconnect rejected: login_id mismatch")
			continue
		}
		c.mu.Lock()
		oldConn := c.conn
		c.conn = conn
		c.enc = enc
		c.pubB64 = pubB64
		c.reconnecting = false
		contacts := make([]string, 0, len(c.contacts))
		for _, id := range c.contacts {
			if looksLikeLoginID(id) && id != c.loginID {
				contacts = append(contacts, id)
			}
		}
		c.mu.Unlock()
		if oldConn != nil && oldConn != conn {
			_ = oldConn.Close()
		}
		c.addEvent("info", "reconnected")
		go c.networkLoop(events)
		if err := c.publishOwnProfile(); err != nil {
			c.addEvent("info", "profile republish failed: "+err.Error())
		}
		if err := c.sendPresenceKeepalive(); err != nil {
			c.addEvent("info", "presence keepalive failed: "+err.Error())
		}
		for _, id := range contacts {
			c.requestProfile(id)
			c.requestPresence(id)
		}
		return
	}
}

func cloneStringMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func cloneInt64Map(m map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func cloneSet(m map[string]struct{}) map[string]struct{} {
	out := make(map[string]struct{}, len(m))
	for k := range m {
		out[k] = struct{}{}
	}
	return out
}

func cloneNonceMap(m map[string]map[string]int64) map[string]map[string]int64 {
	out := make(map[string]map[string]int64, len(m))
	for id, byNonce := range m {
		inner := make(map[string]int64, len(byNonce))
		for nonce, ts := range byNonce {
			inner[nonce] = ts
		}
		out[id] = inner
	}
	return out
}

func (c *webClient) e2eeStatusLocked(loginID string) string {
	if len(c.peerE2EEMulti[loginID]) > 0 {
		if len(c.peerE2EEMulti[loginID]) == 1 {
			return "verified(1)"
		}
		return fmt.Sprintf("verified(%d)", len(c.peerE2EEMulti[loginID]))
	}
	if issue := strings.TrimSpace(c.e2eeIssues[loginID]); issue != "" {
		return "invalid: " + issue
	}
	return "missing"
}

func (c *webClient) dmTargets() []dmTarget {
	c.mu.Lock()
	defer c.mu.Unlock()
	set := make(map[string]struct{})
	for id := range c.friends {
		if looksLikeLoginID(id) && id != c.loginID {
			set[id] = struct{}{}
		}
	}
	for _, id := range c.contacts {
		if looksLikeLoginID(id) && id != c.loginID {
			set[id] = struct{}{}
		}
	}
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		return strings.ToLower(c.displayPeerLocked(ids[i])) < strings.ToLower(c.displayPeerLocked(ids[j]))
	})
	out := make([]dmTarget, 0, len(ids))
	for _, id := range ids {
		out = append(out, dmTarget{
			ID:            id,
			Label:         c.displayPeerLocked(id),
			Nickname:      strings.TrimSpace(c.nicknames[id]),
			ProfileText:   strings.TrimSpace(c.peerProfiles[id]),
			LastRefreshed: c.profileRefreshed[id],
			Online:        strings.TrimSpace(c.presence[id]),
			OnlineTTLSec:  c.presenceTTL[id],
			E2EEReady:     len(c.peerE2EEMulti[id]) > 0,
			E2EEStatus:    c.e2eeStatusLocked(id),
		})
	}
	return out
}

func (c *webClient) pendingFriendRequests() []dmTarget {
	c.mu.Lock()
	defer c.mu.Unlock()
	ids := make([]string, 0, len(c.pendingFriends))
	for id := range c.pendingFriends {
		if !looksLikeLoginID(id) || id == c.loginID {
			continue
		}
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		return strings.ToLower(c.displayPeerLocked(ids[i])) < strings.ToLower(c.displayPeerLocked(ids[j]))
	})
	out := make([]dmTarget, 0, len(ids))
	for _, id := range ids {
		out = append(out, dmTarget{
			ID:            id,
			Label:         c.displayPeerLocked(id),
			Nickname:      strings.TrimSpace(c.nicknames[id]),
			ProfileText:   strings.TrimSpace(c.peerProfiles[id]),
			LastRefreshed: c.pendingFriends[id],
			Online:        strings.TrimSpace(c.presence[id]),
			OnlineTTLSec:  c.presenceTTL[id],
			E2EEReady:     len(c.peerE2EEMulti[id]) > 0,
			E2EEStatus:    c.e2eeStatusLocked(id),
		})
	}
	return out
}

func (c *webClient) pendingChannelInvites() []channelInviteEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]channelInviteEntry, 0, len(c.pendingInvites))
	for _, inv := range c.pendingInvites {
		if strings.TrimSpace(inv.Group) == "" {
			continue
		}
		inv.FromLabel = c.displayPeerLocked(inv.FromID)
		inv.Channel = strings.TrimSpace(inv.Channel)
		inv.InviteKey = channelInviteKey(inv.FromID, inv.Group)
		out = append(out, inv)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ReceivedAt == out[j].ReceivedAt {
			if out[i].Group == out[j].Group {
				return out[i].Channel < out[j].Channel
			}
			return out[i].Group < out[j].Group
		}
		return out[i].ReceivedAt > out[j].ReceivedAt
	})
	return out
}

func (c *webClient) groupsList() []groupEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	names := make([]string, 0, len(c.groups))
	for g := range c.groups {
		names = append(names, g)
	}
	sort.Strings(names)
	out := make([]groupEntry, 0, len(names))
	for _, g := range names {
		channels := make([]string, 0, len(c.groups[g]))
		for ch := range c.groups[g] {
			if strings.TrimSpace(ch) != "" {
				channels = append(channels, ch)
			}
		}
		sort.Strings(channels)
		_, owned := c.ownedGroups[g]
		ownerID := strings.TrimSpace(c.groupOwners[g])
		ownerLabel := ""
		if looksLikeLoginID(ownerID) {
			ownerLabel = c.displayPeerLocked(ownerID)
		}
		out = append(out, groupEntry{Name: g, Channels: channels, Owned: owned, OwnerID: ownerID, OwnerLabel: ownerLabel})
	}
	return out
}

func (c *webClient) persistUIState() {
	groups := c.groupsList()
	c.mu.Lock()
	ctx := c.lastContext
	path := c.uiStatePath
	c.mu.Unlock()
	_ = saveUIState(path, groups, ctx)
}

func (c *webClient) setLastContext(ctx chatContext) {
	ctx.Mode = strings.ToLower(strings.TrimSpace(ctx.Mode))
	if ctx.Mode != "dm" && ctx.Mode != "group" {
		ctx.Mode = ""
	}
	ctx.Target = strings.TrimSpace(ctx.Target)
	ctx.Group = strings.TrimSpace(ctx.Group)
	ctx.Channel = strings.TrimSpace(ctx.Channel)
	if ctx.Mode == "group" && ctx.Channel == "" {
		ctx.Channel = "default"
	}
	c.mu.Lock()
	c.lastContext = ctx
	c.mu.Unlock()
	c.persistUIState()
}

func (c *webClient) handleContextSet(w http.ResponseWriter, r *http.Request) {
	var req chatContext
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	c.setLastContext(req)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (c *webClient) profileCard(loginID string) dmTarget {
	c.mu.Lock()
	defer c.mu.Unlock()
	loginID = strings.TrimSpace(loginID)
	return dmTarget{
		ID:            loginID,
		Label:         c.displayPeerLocked(loginID),
		Nickname:      strings.TrimSpace(c.nicknames[loginID]),
		ProfileText:   strings.TrimSpace(c.peerProfiles[loginID]),
		LastRefreshed: c.profileRefreshed[loginID],
		Online:        strings.TrimSpace(c.presence[loginID]),
		OnlineTTLSec:  c.presenceTTL[loginID],
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func decodeJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	return json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(dst)
}

func (c *webClient) handleBootstrap(w http.ResponseWriter, _ *http.Request) {
	resp := map[string]any{
		"login_id":          c.loginID,
		"display_name":      c.displayName,
		"profile_text":      c.profileText,
		"targets":           c.dmTargets(),
		"pending_friends":   c.pendingFriendRequests(),
		"pending_invites":   c.pendingChannelInvites(),
		"groups":            c.groupsList(),
		"last_context":      c.lastContext,
		"presence_visible":  c.presenceVisible,
		"presence_ttl_sec":  c.presenceTTLSec,
		"presence_ttl_min":  minPresenceTTLSec,
		"presence_ttl_max":  maxPresenceTTLSec,
		"presence_interval": int(presenceKeepaliveInterval / time.Second),
	}
	writeJSON(w, http.StatusOK, resp)
}

func (c *webClient) handleEvents(w http.ResponseWriter, r *http.Request) {
	sinceStr := strings.TrimSpace(r.URL.Query().Get("since"))
	since := int64(0)
	if sinceStr != "" {
		if n, err := strconv.ParseInt(sinceStr, 10, 64); err == nil {
			since = n
		}
	}
	c.mu.Lock()
	items := make([]webEvent, 0)
	for _, e := range c.events {
		if e.Seq > since {
			items = append(items, e)
		}
	}
	c.mu.Unlock()
	targets := c.dmTargets()
	pending := c.pendingFriendRequests()
	invites := c.pendingChannelInvites()
	groups := c.groupsList()
	writeJSON(w, http.StatusOK, map[string]any{"events": items, "targets": targets, "pending_friends": pending, "pending_invites": invites, "groups": groups})
}

func (c *webClient) handleSend(w http.ResponseWriter, r *http.Request) {
	var req struct {
		To   string `json:"to"`
		Text string `json:"text"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	target, ok := c.resolveRecipient(req.To)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown recipient"})
		return
	}
	text := strings.TrimSpace(req.Text)
	if text == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "message text required"})
		return
	}
	encryptedBody, err := c.encryptDirectMessage(target, text)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := c.sendSigned(Packet{Type: "send", To: target, Body: encryptedBody}); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if c.displayPeer(target) == shortID(target) {
		c.requestProfile(target)
	}
	c.addChatEventWithActor(text, c.loginID, "dm", target, "", "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func normalizeGroupName(v string) string {
	return strings.TrimSpace(v)
}

func normalizeChannelName(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "default"
	}
	return v
}

func channelInviteKey(from string, group string) string {
	return strings.TrimSpace(from) + "|" + normalizeGroupName(group)
}

func parseChannelInviteKey(v string) (from string, group string, ok bool) {
	parts := strings.Split(strings.TrimSpace(v), "|")
	if len(parts) != 2 {
		return "", "", false
	}
	from = strings.TrimSpace(parts[0])
	group = normalizeGroupName(parts[1])
	if !looksLikeLoginID(from) || group == "" {
		return "", "", false
	}
	return from, group, true
}

func (c *webClient) handleGroupCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Group   string `json:"group"`
		Channel string `json:"channel"`
		Public  *bool  `json:"public"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	group := normalizeGroupName(req.Group)
	channel := normalizeChannelName(req.Channel)
	if group == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "group required"})
		return
	}
	public := true
	if req.Public != nil {
		public = *req.Public
	}
	if err := c.sendSigned(Packet{Type: "channel_create", Group: group, Channel: channel, Public: public}); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	c.rememberGroup(group, channel)
	c.mu.Lock()
	c.ownedGroups[group] = struct{}{}
	c.groupOwners[group] = c.loginID
	c.mu.Unlock()
	c.persistUIState()
	c.addEvent("info", fmt.Sprintf("group created: %s/%s (%s)", group, channel, map[bool]string{true: "public", false: "private"}[public]))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "group": group, "channel": channel, "public": public})
}

func (c *webClient) handleGroupJoin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Group   string `json:"group"`
		Channel string `json:"channel"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	group := normalizeGroupName(req.Group)
	channel := normalizeChannelName(req.Channel)
	if group == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "group required"})
		return
	}
	if err := c.sendSigned(Packet{Type: "channel_join", Group: group, Channel: channel}); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	c.rememberGroup(group, channel)
	c.addEvent("info", fmt.Sprintf("group join requested: %s/%s", group, channel))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "group": group, "channel": channel})
}

func (c *webClient) handleGroupSend(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Group   string `json:"group"`
		Channel string `json:"channel"`
		Text    string `json:"text"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	group := normalizeGroupName(req.Group)
	channel := normalizeChannelName(req.Channel)
	text := strings.TrimSpace(req.Text)
	if group == "" || text == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "group and text required"})
		return
	}
	if err := c.sendSigned(Packet{Type: "channel_send", Group: group, Channel: channel, Body: text}); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	c.rememberGroup(group, channel)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (c *webClient) handleGroupRemove(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Group string `json:"group"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	group := normalizeGroupName(req.Group)
	if group == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "group required"})
		return
	}
	c.forgetGroup(group)
	c.addEvent("info", "group removed: "+group)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (c *webClient) handleGroupInvite(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Group   string   `json:"group"`
		Channel string   `json:"channel"`
		To      []string `json:"to"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	group := normalizeGroupName(req.Group)
	if group == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "group required"})
		return
	}
	if len(req.To) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "at least one recipient required"})
		return
	}
	sent := 0
	for _, token := range req.To {
		target, ok := c.resolveRecipient(token)
		if !ok {
			continue
		}
		if err := c.sendSigned(Packet{Type: "group_invite", To: target, Group: group, Channel: ""}); err != nil {
			continue
		}
		sent++
	}
	if sent == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no valid recipients"})
		return
	}
	c.rememberGroup(group, "default")
	c.addEvent("info", fmt.Sprintf("group invite sent: %s recipients=%d", group, sent))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "sent": sent})
}

func (c *webClient) handleInviteAccept(w http.ResponseWriter, r *http.Request) {
	var req struct {
		InviteKey string `json:"invite_key"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	from, group, ok := parseChannelInviteKey(req.InviteKey)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid invite key"})
		return
	}
	c.mu.Lock()
	_, exists := c.pendingInvites[channelInviteKey(from, group)]
	c.mu.Unlock()
	if !exists {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invite no longer pending"})
		return
	}
	channel := "default"
	if err := c.sendSigned(Packet{Type: "channel_join", Group: group, Channel: channel}); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	c.mu.Lock()
	delete(c.pendingInvites, channelInviteKey(from, group))
	c.mu.Unlock()
	c.rememberGroup(group, channel)
	c.addEvent("info", fmt.Sprintf("group invite accepted: %s", group))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "group": group, "channel": channel})
}

func (c *webClient) handleInviteIgnore(w http.ResponseWriter, r *http.Request) {
	var req struct {
		InviteKey string `json:"invite_key"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	from, group, ok := parseChannelInviteKey(req.InviteKey)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid invite key"})
		return
	}
	c.mu.Lock()
	delete(c.pendingInvites, channelInviteKey(from, group))
	c.mu.Unlock()
	// Ignore is local-only: dismiss the notice without server action.
	c.addEvent("info", fmt.Sprintf("group invite ignored: %s", group))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (c *webClient) handleInviteReject(w http.ResponseWriter, r *http.Request) {
	var req struct {
		InviteKey string `json:"invite_key"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	from, group, ok := parseChannelInviteKey(req.InviteKey)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid invite key"})
		return
	}
	if err := c.sendSigned(Packet{Type: "group_invite_reject", To: from, Group: group, Channel: ""}); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	c.mu.Lock()
	delete(c.pendingInvites, channelInviteKey(from, group))
	c.mu.Unlock()
	c.addEvent("info", fmt.Sprintf("group invite rejected: %s", group))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (c *webClient) handlePing(w http.ResponseWriter, r *http.Request) {
	var req struct {
		To string `json:"to"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	target, ok := c.resolveRecipient(req.To)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown recipient"})
		return
	}
	id, err := c.sendSignedWithID(Packet{Type: "ping", To: target, Body: "ping"})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	c.mu.Lock()
	c.pendingPings[id] = time.Now().UnixMilli()
	c.mu.Unlock()
	c.addEvent("info", "ping sent to "+c.displayPeer(target))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": id})
}

func (c *webClient) handleFriendAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		To string `json:"to"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	target, ok := c.resolveRecipient(req.To)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown recipient"})
		return
	}
	if err := c.sendSigned(Packet{Type: "friend_add", To: target, Body: c.friendKeyBody()}); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if c.displayPeer(target) == shortID(target) {
		c.requestProfile(target)
	}
	c.addEvent("info", "friend request sent to "+c.displayPeer(target))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (c *webClient) handleFriendAccept(w http.ResponseWriter, r *http.Request) {
	var req struct {
		To string `json:"to"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	target, ok := c.resolveRecipient(req.To)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown recipient"})
		return
	}
	if err := c.sendSigned(Packet{Type: "friend_accept", To: target, Body: c.friendKeyBody()}); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if c.displayPeer(target) == shortID(target) {
		c.requestProfile(target)
	}
	c.mu.Lock()
	delete(c.pendingFriends, target)
	c.mu.Unlock()
	c.addEvent("info", "friend accepted: "+c.displayPeer(target))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (c *webClient) handleFriendIgnore(w http.ResponseWriter, r *http.Request) {
	var req struct {
		To string `json:"to"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	target, ok := c.resolveRecipient(req.To)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown recipient"})
		return
	}
	c.mu.Lock()
	delete(c.pendingFriends, target)
	c.mu.Unlock()
	c.addEvent("info", "friend request ignored: "+c.displayPeer(target))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (c *webClient) rotateE2EEKey() (int, error) {
	priv, pubB64, err := netsec.NewX25519Identity()
	if err != nil {
		return 0, err
	}
	c.mu.Lock()
	e2eePath := strings.TrimSpace(c.e2eePath)
	c.mu.Unlock()
	if e2eePath == "" {
		return 0, fmt.Errorf("missing e2ee key path")
	}
	payload, err := json.MarshalIndent(e2eeKeyFile{PrivateKey: base64.StdEncoding.EncodeToString(priv.Bytes())}, "", "  ")
	if err != nil {
		return 0, err
	}
	if err := writeFileAtomic(e2eePath, payload, 0o600); err != nil {
		return 0, err
	}

	c.mu.Lock()
	c.e2ee = priv
	c.e2eeB64 = pubB64
	friendIDs := make([]string, 0, len(c.friends))
	for id := range c.friends {
		if looksLikeLoginID(id) && id != c.loginID {
			friendIDs = append(friendIDs, id)
		}
	}
	c.mu.Unlock()

	shared := 0
	for _, id := range friendIDs {
		if err := c.sendSigned(Packet{Type: "friend_add", To: id, Body: c.friendKeyBody()}); err == nil {
			shared++
		}
	}
	return shared, nil
}

func (c *webClient) handleE2EERotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	shared, err := c.rotateE2EEKey()
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	c.addEvent("info", fmt.Sprintf("e2ee key rotated; shared with %d friends", shared))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "shared_with": shared})
}

func (c *webClient) handleProfileSet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DisplayName string `json:"display_name"`
		ProfileText string `json:"profile_text"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	name := strings.TrimSpace(req.DisplayName)
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "display_name required"})
		return
	}
	text := strings.TrimSpace(req.ProfileText)
	c.mu.Lock()
	c.displayName = name
	c.profileText = text
	nicks := cloneStringMap(c.nicknames)
	peers := cloneStringMap(c.peerProfiles)
	refs := cloneInt64Map(c.profileRefreshed)
	c.mu.Unlock()
	if err := saveProfile(c.profilePath, name, text, nicks, peers, refs); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := c.publishOwnProfile(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	c.addEvent("info", "profile updated")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (c *webClient) handleProfileGet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		To string `json:"to"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	target, ok := c.resolveRecipient(req.To)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown recipient"})
		return
	}
	c.requestProfile(target)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (c *webClient) handlePresenceCheck(w http.ResponseWriter, r *http.Request) {
	var req struct {
		To string `json:"to"`
	}
	if r.ContentLength > 0 {
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
	}
	if strings.TrimSpace(req.To) != "" {
		target, ok := c.resolveRecipient(req.To)
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown recipient"})
			return
		}
		c.requestPresence(target)
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	targets := c.dmTargets()
	for _, t := range targets {
		c.requestPresence(t.ID)
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (c *webClient) handlePresenceSet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Visible *bool `json:"visible"`
		TTLSec  *int  `json:"ttl_sec"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	c.mu.Lock()
	visible := c.presenceVisible
	ttl := c.presenceTTLSec
	c.mu.Unlock()
	if req.Visible != nil {
		visible = *req.Visible
	}
	if req.TTLSec != nil {
		ttl = *req.TTLSec
	}
	if err := c.setOwnPresenceConfig(visible, ttl); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	mode := "invisible"
	if visible {
		mode = "visible"
	}
	ttl = normalizePresenceTTLSec(ttl)
	c.addEvent("info", fmt.Sprintf("presence updated: %s ttl=%ds", mode, ttl))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"visible": visible,
		"ttl_sec": ttl,
	})
}

func (c *webClient) handleTargets(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"targets": c.dmTargets(), "pending_friends": c.pendingFriendRequests(), "pending_invites": c.pendingChannelInvites()})
}

func (c *webClient) handleGroups(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"groups": c.groupsList()})
}

func (c *webClient) handleProfileCard(w http.ResponseWriter, r *http.Request) {
	loginID := strings.TrimSpace(r.URL.Query().Get("id"))
	if !looksLikeLoginID(loginID) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"profile": c.profileCard(loginID)})
}

//go:embed webui.html
var uiFS embed.FS

func pageTemplate() (*template.Template, error) {
	body, err := uiFS.ReadFile("webui.html")
	if err != nil {
		return nil, err
	}
	return template.New("webui").Parse(string(body))
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
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
	f := uiStateFile{Groups: groups, LastContext: ctx}
	payload, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, payload, 0o600)
}

func loadProfile(path string) (string, string, map[string]string, map[string]string, map[string]int64, error) {
	nicks := make(map[string]string)
	peers := make(map[string]string)
	refs := make(map[string]int64)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", "", nicks, peers, refs, nil
		}
		return "", "", nil, nil, nil, err
	}
	var f profileFile
	if err := json.Unmarshal(data, &f); err != nil {
		return "", "", nil, nil, nil, err
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
		if p.RefreshedAt > 0 {
			refs[id] = p.RefreshedAt
		}
	}
	return strings.TrimSpace(f.DisplayName), strings.TrimSpace(f.ProfileText), nicks, peers, refs, nil
}

func saveProfile(path string, displayName string, profileText string, nicknames map[string]string, peerProfiles map[string]string, refreshed map[string]int64) error {
	existingName, existingText, existingNicks, existingPeers, existingRefs, err := loadProfile(path)
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
	mergedRefs := make(map[string]int64, len(existingRefs)+len(refreshed))
	for id, ts := range existingRefs {
		mergedRefs[id] = ts
	}
	for id, ts := range refreshed {
		if ts > 0 {
			mergedRefs[id] = ts
		}
	}
	name := strings.TrimSpace(displayName)
	if name == "" {
		name = strings.TrimSpace(existingName)
	}
	text := strings.TrimSpace(profileText)
	if text == "" {
		text = strings.TrimSpace(existingText)
	}
	return writeProfileAtomic(path, name, text, mergedNicks, mergedPeers, mergedRefs)
}

func writeProfileAtomic(path string, displayName string, profileText string, nicknames map[string]string, peerProfiles map[string]string, refreshed map[string]int64) error {
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
		f.PeerProfiles = append(f.PeerProfiles, savedProfile{LoginID: id, ProfileText: text, RefreshedAt: refreshed[id]})
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

func shortID(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 12 {
		return s
	}
	return s[:12]
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
	msg, err := json.Marshal(signedAction{Type: p.Type, ID: p.ID, From: p.From, To: p.To, Body: p.Body, Compression: p.Compression, USize: p.USize, Group: p.Group, Channel: p.Channel, Public: p.Public, CreatedAt: p.CreatedAt})
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

	events := make(chan netMsg, 64)
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
		name, _, _, _, _, _ := loadProfile(profilePathForKey(home, p))
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

func main() {
	serverAddr := flag.String("addr", "127.0.0.1:9101", "server address")
	webAddr := flag.String("web", "127.0.0.1:0", "local web server listen address (default ephemeral port)")
	keyPath := flag.String("key", "", "private key file path")
	contactsPath := flag.String("contacts", "", "contacts file path")
	profilePath := flag.String("profile", "", "profile file path")
	autoOpen := flag.Bool("open", true, "auto-open browser")
	flag.Parse()

	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("unable to resolve home directory: %v", err)
	}
	if strings.TrimSpace(*keyPath) == "" {
		*keyPath = filepath.Join(home, ".goaccord", "ed25519_key.json")
	}
	selectedStartupKeyPath, err := promptIdentityPath(home, *keyPath, false)
	if err != nil {
		log.Fatalf("identity selection failed: %v", err)
	}
	*keyPath = selectedStartupKeyPath
	if strings.TrimSpace(*contactsPath) == "" {
		*contactsPath = filepath.Join(home, ".goaccord", "contacts.json")
	}
	if strings.TrimSpace(*profilePath) == "" {
		*profilePath = filepath.Join(home, ".goaccord", "profiles", "profile-"+filepath.Base(strings.TrimSpace(*keyPath))+".json")
	}

	selectedKeyPath, priv, conn, enc, events, loginID, pubB64, err := connectWithIdentitySelection(*serverAddr, home, *keyPath)
	if err != nil {
		log.Fatalf("connect/auth failed: %v", err)
	}
	*keyPath = selectedKeyPath
	e2eePath := e2eePathForKey(home, *keyPath)
	e2eeStatePath := e2eeStatePathForKey(home, *keyPath)
	e2eePriv, e2eePubB64, err := loadOrCreateE2EEKey(e2eePath)
	if err != nil {
		log.Fatalf("e2ee key load failed: %v", err)
	}
	peerE2EEMulti, friendKeyNonces, err := loadE2EEState(e2eeStatePath)
	if err != nil {
		log.Fatalf("e2ee state load failed: %v", err)
	}

	contacts, err := loadContacts(*contactsPath)
	if err != nil {
		log.Fatalf("contacts load failed: %v", err)
	}
	displayName, profileText, nicknames, peerProfiles, profileRefreshed, err := loadProfile(*profilePath)
	if err != nil {
		log.Fatalf("profile load failed: %v", err)
	}
	uiStatePath := uiStatePathForProfile(*profilePath)
	savedGroups, savedCtx, err := loadUIState(uiStatePath)
	if err != nil {
		log.Fatalf("ui state load failed: %v", err)
	}
	if strings.TrimSpace(displayName) == "" {
		displayName = promptDisplayName(displayName)
		if err := saveProfile(*profilePath, displayName, profileText, nicknames, peerProfiles, profileRefreshed); err != nil {
			log.Fatalf("profile save failed: %v", err)
		}
	}

	client := &webClient{
		enc:              enc,
		conn:             conn,
		priv:             priv,
		pubB64:           pubB64,
		e2ee:             e2eePriv,
		e2eeB64:          e2eePubB64,
		loginID:          loginID,
		displayName:      displayName,
		profileText:      profileText,
		contactsPath:     *contactsPath,
		profilePath:      *profilePath,
		uiStatePath:      uiStatePath,
		e2eePath:         e2eePath,
		e2eeStatePath:    e2eeStatePath,
		contacts:         contacts,
		nicknames:        nicknames,
		peerProfiles:     peerProfiles,
		profileRefreshed: profileRefreshed,
		presence:         make(map[string]string),
		presenceTTL:      make(map[string]int),
		presenceVisible:  true,
		presenceTTLSec:   defaultPresenceTTLSec,
		friends:          make(map[string]struct{}),
		pendingFriends:   make(map[string]int64),
		pendingInvites:   make(map[string]channelInviteEntry),
		groups:           make(map[string]map[string]struct{}),
		ownedGroups:      make(map[string]struct{}),
		groupOwners:      make(map[string]string),
		lastContext:      savedCtx,
		pendingPings:     make(map[string]int64),
		seenChatIDs:      make(map[string]struct{}),
		peerE2EEMulti:    peerE2EEMulti,
		friendKeyNonces:  friendKeyNonces,
		e2eeIssues:       make(map[string]string),
		serverAddr:       *serverAddr,
	}
	for _, g := range savedGroups {
		group := strings.TrimSpace(g.Name)
		if group == "" {
			continue
		}
		if len(g.Channels) == 0 {
			client.rememberGroup(group, "default")
			if g.Owned {
				client.ownedGroups[group] = struct{}{}
			}
			if looksLikeLoginID(strings.TrimSpace(g.OwnerID)) {
				client.groupOwners[group] = strings.TrimSpace(g.OwnerID)
			}
			continue
		}
		for _, ch := range g.Channels {
			client.rememberGroup(group, ch)
		}
		if g.Owned {
			client.ownedGroups[group] = struct{}{}
		}
		if looksLikeLoginID(strings.TrimSpace(g.OwnerID)) {
			client.groupOwners[group] = strings.TrimSpace(g.OwnerID)
		}
	}
	client.addEvent("info", "connected to "+*serverAddr)
	client.addEvent("info", "login_id: "+loginID)
	client.addEvent("info", "display name: "+displayName)
	if err := client.publishOwnProfile(); err != nil {
		client.addEvent("info", "profile publish failed: "+err.Error())
	}
	if err := client.sendPresenceKeepalive(); err != nil {
		client.addEvent("info", "presence keepalive failed: "+err.Error())
	}
	for _, id := range contacts {
		client.requestProfile(id)
	}

	go client.networkLoop(events)
	go func() {
		t := time.NewTicker(presenceKeepaliveInterval)
		defer t.Stop()
		for range t.C {
			if err := client.sendPresenceKeepalive(); err != nil {
				client.addEvent("info", "presence keepalive failed: "+err.Error())
			}
		}
	}()

	tpl, err := pageTemplate()
	if err != nil {
		log.Fatalf("template load failed: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_ = tpl.Execute(w, map[string]any{"Title": "goAccord Web Client"})
	})
	mux.HandleFunc("/api/bootstrap", client.handleBootstrap)
	mux.HandleFunc("/api/events", client.handleEvents)
	mux.HandleFunc("/api/targets", client.handleTargets)
	mux.HandleFunc("/api/groups", client.handleGroups)
	mux.HandleFunc("/api/send", client.handleSend)
	mux.HandleFunc("/api/group/create", client.handleGroupCreate)
	mux.HandleFunc("/api/group/join", client.handleGroupJoin)
	mux.HandleFunc("/api/group/send", client.handleGroupSend)
	mux.HandleFunc("/api/group/remove", client.handleGroupRemove)
	mux.HandleFunc("/api/group/invite", client.handleGroupInvite)
	mux.HandleFunc("/api/context/set", client.handleContextSet)
	mux.HandleFunc("/api/ping", client.handlePing)
	mux.HandleFunc("/api/friend/add", client.handleFriendAdd)
	mux.HandleFunc("/api/friend/accept", client.handleFriendAccept)
	mux.HandleFunc("/api/friend/ignore", client.handleFriendIgnore)
	mux.HandleFunc("/api/invite/accept", client.handleInviteAccept)
	mux.HandleFunc("/api/invite/ignore", client.handleInviteIgnore)
	mux.HandleFunc("/api/invite/reject", client.handleInviteReject)
	mux.HandleFunc("/api/e2ee/rotate", client.handleE2EERotate)
	mux.HandleFunc("/api/profile/set", client.handleProfileSet)
	mux.HandleFunc("/api/profile/get", client.handleProfileGet)
	mux.HandleFunc("/api/presence/check", client.handlePresenceCheck)
	mux.HandleFunc("/api/presence/set", client.handlePresenceSet)
	mux.HandleFunc("/api/profile/card", client.handleProfileCard)

	ln, err := net.Listen("tcp", *webAddr)
	if err != nil {
		log.Fatalf("web listen failed: %v", err)
	}
	defer ln.Close()
	url := "http://" + ln.Addr().String()
	log.Printf("web client listening on %s", url)
	if *autoOpen {
		openBrowser(url)
	}
	if err := http.Serve(ln, mux); err != nil {
		log.Fatalf("web server failed: %v", err)
	}
}
