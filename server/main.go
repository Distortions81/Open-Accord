package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultMaxMessageBytes = 16 * 1024
	defaultMaxMsgsPerSec   = 50
	defaultBurstMessages   = 100
	defaultMaxSeenEntries  = 20000
	defaultMaxKnownAddrs   = 5000
	defaultKnownAddrTTL    = 30 * time.Minute
	defaultPeerBanScore    = 20
	defaultPeerBanFor      = 10 * time.Minute
	clientModeDisabled     = "disabled"
	clientModePublic       = "public"
	clientModePrivate      = "private"
)

type Packet struct {
	Type          string   `json:"type"`
	Role          string   `json:"role,omitempty"`
	ID            string   `json:"id,omitempty"`
	From          string   `json:"from,omitempty"`
	To            string   `json:"to,omitempty"`
	Body          string   `json:"body,omitempty"`
	Origin        string   `json:"origin,omitempty"`
	Nonce         string   `json:"nonce,omitempty"`
	PubKey        string   `json:"pub_key,omitempty"`
	Sig           string   `json:"sig,omitempty"`
	Listen        string   `json:"listen,omitempty"`
	Addrs         []string `json:"addrs,omitempty"`
	MaxMsgBytes   int      `json:"max_msg_bytes,omitempty"`
	MaxMsgsPerSec int      `json:"max_msgs_per_sec,omitempty"`
	Burst         int      `json:"burst,omitempty"`
	Caps          []string `json:"caps,omitempty"`
}

type Conn struct {
	conn net.Conn
	enc  *json.Encoder
	mu   sync.Mutex
}

func (c *Conn) Send(p Packet) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.enc.Encode(p)
}

type signedAction struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	From string `json:"from"`
	To   string `json:"to,omitempty"`
	Body string `json:"body,omitempty"`
}

type keyFile struct {
	PrivateKey string `json:"private_key"`
}

type Peer struct {
	conn          *Conn
	addr          string
	maxMsgBytes   int
	maxMsgsPerSec int
	burst         int
	caps          map[string]struct{}
}

type rateLimiter struct {
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

func newRateLimiter(msgsPerSec int, burst int) *rateLimiter {
	r := float64(msgsPerSec)
	b := float64(burst)
	if r <= 0 {
		r = float64(defaultMaxMsgsPerSec)
	}
	if b <= 0 {
		b = float64(defaultBurstMessages)
	}
	now := time.Now()
	return &rateLimiter{rate: r, burst: b, tokens: b, last: now}
}

func (rl *rateLimiter) Allow() bool {
	now := time.Now()
	elapsed := now.Sub(rl.last).Seconds()
	rl.last = now
	rl.tokens += elapsed * rl.rate
	if rl.tokens > rl.burst {
		rl.tokens = rl.burst
	}
	if rl.tokens < 1 {
		return false
	}
	rl.tokens--
	return true
}

type Server struct {
	id              string
	ownerPubKeyB64  string
	ownerPriv       ed25519.PrivateKey
	advertiseAddr   string
	maxPeerSessions int
	maxMessageBytes int
	maxMsgsPerSec   int
	burstMessages   int
	maxSeenEntries  int
	maxKnownAddrs   int
	knownAddrTTL    time.Duration
	relayEnabled    bool
	clientMode      string
	clientAllow     map[string]struct{}

	mu           sync.RWMutex
	users        map[string]*Conn
	peers        map[string]*Peer
	seen         map[string]time.Time
	knownAddrs   map[string]time.Time
	dialing      map[string]struct{}
	peerScore    map[string]int
	peerBanned   map[string]time.Time
	peerBanScore int
	peerBanFor   time.Duration

	counter atomic.Uint64
}

func NewServer(id, ownerPubKeyB64 string, ownerPriv ed25519.PrivateKey, advertiseAddr string, maxPeerSessions int, maxMessageBytes int, maxMsgsPerSec int, burstMessages int, maxSeenEntries int, maxKnownAddrs int, knownAddrTTL time.Duration) *Server {
	if maxMessageBytes <= 0 {
		maxMessageBytes = defaultMaxMessageBytes
	}
	if maxMsgsPerSec <= 0 {
		maxMsgsPerSec = defaultMaxMsgsPerSec
	}
	if burstMessages <= 0 {
		burstMessages = defaultBurstMessages
	}
	if maxSeenEntries <= 0 {
		maxSeenEntries = defaultMaxSeenEntries
	}
	if maxKnownAddrs <= 0 {
		maxKnownAddrs = defaultMaxKnownAddrs
	}
	if knownAddrTTL <= 0 {
		knownAddrTTL = defaultKnownAddrTTL
	}

	return &Server{
		id:              id,
		ownerPubKeyB64:  ownerPubKeyB64,
		ownerPriv:       ownerPriv,
		advertiseAddr:   normalizeAddr(advertiseAddr),
		maxPeerSessions: maxPeerSessions,
		maxMessageBytes: maxMessageBytes,
		maxMsgsPerSec:   maxMsgsPerSec,
		burstMessages:   burstMessages,
		maxSeenEntries:  maxSeenEntries,
		maxKnownAddrs:   maxKnownAddrs,
		knownAddrTTL:    knownAddrTTL,
		relayEnabled:    true,
		clientMode:      clientModePublic,
		clientAllow:     make(map[string]struct{}),
		users:           make(map[string]*Conn),
		peers:           make(map[string]*Peer),
		seen:            make(map[string]time.Time),
		knownAddrs:      make(map[string]time.Time),
		dialing:         make(map[string]struct{}),
		peerScore:       make(map[string]int),
		peerBanned:      make(map[string]time.Time),
		peerBanScore:    defaultPeerBanScore,
		peerBanFor:      defaultPeerBanFor,
	}
}

func readPacketLine(reader *bufio.Reader, maxBytes int, out *Packet) (decoded bool, oversized bool, err error) {
	if maxBytes <= 0 {
		maxBytes = defaultMaxMessageBytes
	}

	line := make([]byte, 0, 256)
	for {
		frag, readErr := reader.ReadSlice('\n')
		line = append(line, frag...)

		if len(line) > maxBytes {
			for readErr == bufio.ErrBufferFull {
				_, readErr = reader.ReadSlice('\n')
			}
			if readErr != nil && readErr != io.EOF {
				return false, true, readErr
			}
			return false, true, nil
		}

		if readErr == bufio.ErrBufferFull {
			continue
		}
		if readErr != nil {
			if readErr == io.EOF {
				if len(strings.TrimSpace(string(line))) == 0 {
					return false, false, io.EOF
				}
			} else {
				return false, false, readErr
			}
		}

		trimmed := strings.TrimSpace(string(line))
		if trimmed == "" {
			if readErr == io.EOF {
				return false, false, io.EOF
			}
			return false, false, nil
		}
		if err := json.Unmarshal([]byte(trimmed), out); err != nil {
			return false, false, nil
		}
		return true, false, nil
	}
}

func (s *Server) readPacket(reader *bufio.Reader, rl *rateLimiter, out *Packet) error {
	for {
		decoded, oversized, err := readPacketLine(reader, s.maxMessageBytes, out)
		if err != nil {
			return err
		}
		if oversized {
			continue
		}
		if !decoded {
			continue
		}
		if rl != nil && !rl.Allow() {
			continue
		}
		return nil
	}
}

func capsToMap(caps []string) map[string]struct{} {
	m := make(map[string]struct{}, len(caps))
	for _, c := range caps {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		m[c] = struct{}{}
	}
	return m
}

func (s *Server) localCaps() []string {
	caps := []string{"transport"}
	if s.relayEnabled {
		caps = append(caps, "relay")
	}
	switch s.clientMode {
	case clientModeDisabled:
		caps = append(caps, "client_disabled")
	case clientModePrivate:
		caps = append(caps, "client_private")
	default:
		caps = append(caps, "client_public")
	}
	return caps
}

func (s *Server) isClientAllowed(loginID string) bool {
	if s.clientMode == clientModeDisabled {
		return false
	}
	if s.clientMode == clientModePublic {
		return true
	}
	s.mu.RLock()
	_, ok := s.clientAllow[loginID]
	s.mu.RUnlock()
	return ok
}

func (s *Server) nextMessageID() string {
	n := s.counter.Add(1)
	return fmt.Sprintf("%s-%d-%d", s.id, time.Now().UnixNano(), n)
}

func loginIDForPubKey(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

func composeServerID(ownerLoginID, localServerID string) (string, error) {
	ownerLoginID = strings.TrimSpace(ownerLoginID)
	localServerID = strings.TrimSpace(localServerID)
	if ownerLoginID == "" {
		return "", fmt.Errorf("owner login id is required")
	}
	if localServerID == "" {
		return "", fmt.Errorf("local server id is required")
	}
	if strings.Contains(ownerLoginID, ":") || strings.Contains(localServerID, ":") {
		return "", fmt.Errorf("':' is not allowed in owner or sid")
	}
	return ownerLoginID + ":" + localServerID, nil
}

func parseServerID(serverID string) (ownerLoginID string, localServerID string, ok bool) {
	parts := strings.Split(serverID, ":")
	if len(parts) != 2 {
		return "", "", false
	}
	owner := strings.TrimSpace(parts[0])
	local := strings.TrimSpace(parts[1])
	if owner == "" || local == "" {
		return "", "", false
	}
	return owner, local, true
}

func signServerIdentity(priv ed25519.PrivateKey, serverID string) (string, error) {
	sig := ed25519.Sign(priv, []byte("server:"+serverID))
	return base64.StdEncoding.EncodeToString(sig), nil
}

func verifyServerIdentity(serverID, pubKeyB64, sigB64 string) bool {
	owner, _, ok := parseServerID(serverID)
	if !ok {
		return false
	}

	pubRaw, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil || len(pubRaw) != ed25519.PublicKeySize {
		return false
	}
	if loginIDForPubKey(pubRaw) != owner {
		return false
	}

	sigRaw, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || len(sigRaw) != ed25519.SignatureSize {
		return false
	}

	return ed25519.Verify(pubRaw, []byte("server:"+serverID), sigRaw)
}

func signAction(priv ed25519.PrivateKey, p Packet) (string, error) {
	msg, err := json.Marshal(signedAction{Type: p.Type, ID: p.ID, From: p.From, To: p.To, Body: p.Body})
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, msg)
	return base64.StdEncoding.EncodeToString(sig), nil
}

func verifyActionSignature(p Packet) bool {
	pubRaw, err := base64.StdEncoding.DecodeString(p.PubKey)
	if err != nil || len(pubRaw) != ed25519.PublicKeySize {
		return false
	}
	if loginIDForPubKey(pubRaw) != p.From {
		return false
	}
	sigRaw, err := base64.StdEncoding.DecodeString(p.Sig)
	if err != nil || len(sigRaw) != ed25519.SignatureSize {
		return false
	}
	msg, err := json.Marshal(signedAction{Type: p.Type, ID: p.ID, From: p.From, To: p.To, Body: p.Body})
	if err != nil {
		return false
	}
	return ed25519.Verify(pubRaw, msg, sigRaw)
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

func normalizeAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	h, p, err := net.SplitHostPort(addr)
	if err != nil || strings.TrimSpace(p) == "" {
		return ""
	}
	h = strings.TrimSpace(h)
	if h == "" || h == "0.0.0.0" || h == "::" || h == "[::]" {
		return ""
	}
	return net.JoinHostPort(h, p)
}

func (s *Server) isPeerBanned(addr string) bool {
	addr = normalizeAddr(addr)
	if addr == "" {
		return false
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	until, ok := s.peerBanned[addr]
	if !ok {
		return false
	}
	if now.After(until) {
		delete(s.peerBanned, addr)
		delete(s.peerScore, addr)
		return false
	}
	return true
}

func (s *Server) penalizePeer(addr string, points int, reason string) bool {
	addr = normalizeAddr(addr)
	if addr == "" {
		return false
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if until, ok := s.peerBanned[addr]; ok && now.Before(until) {
		return true
	}
	s.peerScore[addr] += points
	if s.peerScore[addr] >= s.peerBanScore {
		s.peerBanned[addr] = now.Add(s.peerBanFor)
		s.peerScore[addr] = 0
		log.Printf("peer %s banned for %s (%s)", addr, s.peerBanFor, reason)
		return true
	}
	return false
}

func (s *Server) trimKnownAddrsLocked(now time.Time) {
	if s.knownAddrTTL > 0 {
		cutoff := now.Add(-s.knownAddrTTL)
		for addr, ts := range s.knownAddrs {
			if ts.Before(cutoff) {
				delete(s.knownAddrs, addr)
			}
		}
	}
	for len(s.knownAddrs) > s.maxKnownAddrs {
		var oldestAddr string
		var oldestTime time.Time
		first := true
		for addr, ts := range s.knownAddrs {
			if first || ts.Before(oldestTime) {
				first = false
				oldestAddr = addr
				oldestTime = ts
			}
		}
		if oldestAddr == "" {
			break
		}
		delete(s.knownAddrs, oldestAddr)
	}
}

func (s *Server) addKnownAddr(addr string) bool {
	addr = normalizeAddr(addr)
	if addr == "" {
		return false
	}
	if s.advertiseAddr != "" && addr == s.advertiseAddr {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, existed := s.knownAddrs[addr]
	s.knownAddrs[addr] = time.Now()
	s.trimKnownAddrsLocked(time.Now())
	return !existed
}

func (s *Server) nextDialCandidate() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.trimKnownAddrsLocked(time.Now())
	if len(s.peers) >= s.maxPeerSessions {
		return ""
	}
	for addr := range s.knownAddrs {
		if s.advertiseAddr != "" && addr == s.advertiseAddr {
			continue
		}
		if _, ok := s.dialing[addr]; ok {
			continue
		}
		connected := false
		for _, peer := range s.peers {
			if peer.addr == addr {
				connected = true
				break
			}
		}
		if connected {
			continue
		}
		s.dialing[addr] = struct{}{}
		return addr
	}
	return ""
}

func (s *Server) clearDialing(addr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.dialing, addr)
}

func (s *Server) peerAddrSnapshot(limit int) []string {
	s.mu.Lock()
	s.trimKnownAddrsLocked(time.Now())
	out := make([]string, 0, limit+1)
	if s.advertiseAddr != "" {
		out = append(out, s.advertiseAddr)
	}
	for addr := range s.knownAddrs {
		if len(out) >= limit {
			break
		}
		out = append(out, addr)
	}
	s.mu.Unlock()
	return out
}

func (s *Server) trimSeenLocked(now time.Time, ttl time.Duration) {
	if ttl > 0 {
		cutoff := now.Add(-ttl)
		for id, ts := range s.seen {
			if ts.Before(cutoff) {
				delete(s.seen, id)
			}
		}
	}
	for len(s.seen) > s.maxSeenEntries {
		var oldestID string
		var oldestTime time.Time
		first := true
		for id, ts := range s.seen {
			if first || ts.Before(oldestTime) {
				first = false
				oldestID = id
				oldestTime = ts
			}
		}
		if oldestID == "" {
			break
		}
		delete(s.seen, oldestID)
	}
}

func (s *Server) markSeen(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.seen[id]; ok {
		return false
	}
	s.seen[id] = time.Now()
	s.trimSeenLocked(time.Now(), 0)
	return true
}

func (s *Server) cleanupSeen(ttl time.Duration) {
	ticker := time.NewTicker(ttl / 2)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		s.trimSeenLocked(time.Now(), ttl)
		s.mu.Unlock()
	}
}

func (s *Server) peerManager() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		addr := s.nextDialCandidate()
		if addr == "" {
			continue
		}
		go func(target string) {
			defer s.clearDialing(target)
			s.dialPeer(target)
		}(addr)
	}
}

func (s *Server) addUser(name string, c *Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[name]; exists {
		return false
	}
	s.users[name] = c
	return true
}

func (s *Server) removeUser(name string, c *Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.users[name]; ok && existing == c {
		delete(s.users, name)
	}
}

func (s *Server) addPeer(peerID, addr string, c *Conn, maxMsgBytes int, maxMsgsPerSec int, burst int, caps []string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.peers[peerID]; ok {
		if existing.conn == c {
			return true
		}
		return false
	}
	if maxMsgBytes <= 0 {
		maxMsgBytes = s.maxMessageBytes
	}
	if maxMsgsPerSec <= 0 {
		maxMsgsPerSec = s.maxMsgsPerSec
	}
	if burst <= 0 {
		burst = s.burstMessages
	}
	s.peers[peerID] = &Peer{conn: c, addr: addr, maxMsgBytes: maxMsgBytes, maxMsgsPerSec: maxMsgsPerSec, burst: burst, caps: capsToMap(caps)}
	return true
}

func (s *Server) removePeer(peerID string, c *Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.peers[peerID]; ok && existing.conn == c {
		delete(s.peers, peerID)
	}
}

func (s *Server) sendToUser(to string, p Packet) bool {
	s.mu.RLock()
	user := s.users[to]
	s.mu.RUnlock()
	if user == nil {
		return false
	}
	if err := user.Send(p); err != nil {
		log.Printf("deliver to user %q failed: %v", to, err)
		return false
	}
	return true
}

func (s *Server) floodToPeers(exceptID string, p Packet) {
	raw, _ := json.Marshal(p)
	type target struct {
		id          string
		conn        *Conn
		maxMsgBytes int
		canRelay    bool
	}

	s.mu.RLock()
	targets := make([]target, 0, len(s.peers))
	for peerID, peer := range s.peers {
		if peerID == exceptID {
			continue
		}
		_, canRelay := peer.caps["relay"]
		targets = append(targets, target{id: peerID, conn: peer.conn, maxMsgBytes: peer.maxMsgBytes, canRelay: canRelay})
	}
	s.mu.RUnlock()

	for _, t := range targets {
		if !t.canRelay {
			continue
		}
		if t.maxMsgBytes > 0 && len(raw) > t.maxMsgBytes {
			continue
		}
		if err := t.conn.Send(p); err != nil {
			log.Printf("forward to peer %q failed: %v", t.id, err)
		}
	}
}

func (s *Server) sendAddr(c *Conn) {
	_ = c.Send(Packet{Type: "addr", Addrs: s.peerAddrSnapshot(64)})
}

func (s *Server) authenticateUser(c *Conn, reader *bufio.Reader, claimedPubKey string) (string, error) {
	nonce := s.nextMessageID()
	if err := c.Send(Packet{Type: "challenge", Nonce: nonce}); err != nil {
		return "", err
	}

	_ = c.conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	defer func() { _ = c.conn.SetReadDeadline(time.Time{}) }()

	var auth Packet
	if err := s.readPacket(reader, nil, &auth); err != nil {
		return "", err
	}
	if auth.Type != "auth" {
		return "", fmt.Errorf("expected auth packet")
	}
	if strings.TrimSpace(auth.PubKey) == "" || strings.TrimSpace(auth.Sig) == "" {
		return "", fmt.Errorf("pubkey and signature required")
	}
	if strings.TrimSpace(claimedPubKey) != "" && strings.TrimSpace(auth.PubKey) != strings.TrimSpace(claimedPubKey) {
		return "", fmt.Errorf("pubkey mismatch")
	}

	pubRaw, err := base64.StdEncoding.DecodeString(auth.PubKey)
	if err != nil || len(pubRaw) != ed25519.PublicKeySize {
		return "", fmt.Errorf("invalid pubkey")
	}
	sigRaw, err := base64.StdEncoding.DecodeString(auth.Sig)
	if err != nil || len(sigRaw) != ed25519.SignatureSize {
		return "", fmt.Errorf("invalid signature")
	}

	if !ed25519.Verify(pubRaw, []byte("login:"+nonce), sigRaw) {
		return "", fmt.Errorf("signature verification failed")
	}

	return loginIDForPubKey(pubRaw), nil
}

func (s *Server) handleUser(loginID string, c *Conn, reader *bufio.Reader, rl *rateLimiter) {
	if !s.addUser(loginID, c) {
		_ = c.Send(Packet{Type: "error", Body: "login id already connected"})
		_ = c.conn.Close()
		return
	}
	defer func() {
		s.removeUser(loginID, c)
		_ = c.conn.Close()
		log.Printf("user disconnected: %s", loginID)
	}()

	_ = c.Send(Packet{Type: "ok", ID: loginID, Body: "authenticated"})
	log.Printf("user connected: %s", loginID)

	for {
		var p Packet
		if err := s.readPacket(reader, rl, &p); err != nil {
			if err != io.EOF {
				log.Printf("user %s read error: %v", loginID, err)
			}
			return
		}
		s.handleUserPacket(loginID, p)
	}
}

func (s *Server) handleUserPacket(sender string, p Packet) {
	if p.Type != "send" {
		return
	}
	if strings.TrimSpace(p.ID) == "" || strings.TrimSpace(p.From) == "" || strings.TrimSpace(p.To) == "" || strings.TrimSpace(p.Body) == "" {
		return
	}
	if p.From != sender {
		return
	}
	if !verifyActionSignature(p) {
		return
	}
	if !s.markSeen(p.ID) {
		return
	}

	s.sendToUser(p.To, Packet{Type: "deliver", ID: p.ID, From: p.From, To: p.To, Body: p.Body, Origin: s.id, PubKey: p.PubKey, Sig: p.Sig})
	if s.relayEnabled {
		s.floodToPeers("", p)
	}
}

func (s *Server) handlePeer(peerID, peerAddr string, c *Conn, reader *bufio.Reader, rl *rateLimiter, remoteMaxMsgBytes int, remoteMaxMsgsPerSec int, remoteBurst int, remoteCaps []string) {
	if !s.addPeer(peerID, peerAddr, c, remoteMaxMsgBytes, remoteMaxMsgsPerSec, remoteBurst, remoteCaps) {
		_ = c.Send(Packet{Type: "error", Body: "duplicate peer id"})
		_ = c.conn.Close()
		return
	}
	defer func() {
		s.removePeer(peerID, c)
		_ = c.conn.Close()
		log.Printf("peer disconnected: %s (%s)", peerID, peerAddr)
	}()

	if peerAddr != "" {
		s.addKnownAddr(peerAddr)
	}
	log.Printf("peer connected: %s (%s)", peerID, peerAddr)

	_ = c.Send(Packet{Type: "getaddr"})
	s.sendAddr(c)

	for {
		var p Packet
		if err := s.readPacket(reader, rl, &p); err != nil {
			if err != io.EOF {
				log.Printf("peer %s read error: %v", peerID, err)
			}
			return
		}
		if !s.handlePeerPacket(peerID, peerAddr, c, p) {
			return
		}
	}
}

func (s *Server) handlePeerPacket(fromPeer, peerAddr string, c *Conn, p Packet) bool {
	switch p.Type {
	case "send":
		if strings.TrimSpace(p.ID) == "" || strings.TrimSpace(p.From) == "" || strings.TrimSpace(p.To) == "" || strings.TrimSpace(p.Body) == "" {
			if s.penalizePeer(peerAddr, 2, "malformed send packet") {
				return false
			}
			return true
		}
		if !verifyActionSignature(p) {
			if s.penalizePeer(peerAddr, 5, "invalid message signature") {
				return false
			}
			return true
		}
		if !s.markSeen(p.ID) {
			return true
		}
		s.sendToUser(p.To, Packet{Type: "deliver", ID: p.ID, From: p.From, To: p.To, Body: p.Body, Origin: s.id, PubKey: p.PubKey, Sig: p.Sig})
		if s.relayEnabled {
			s.floodToPeers(fromPeer, p)
		}
		return true
	case "getaddr":
		s.sendAddr(c)
		return true
	case "addr":
		for _, a := range p.Addrs {
			_ = s.addKnownAddr(a)
		}
		return true
	default:
		if s.penalizePeer(peerAddr, 1, "unknown packet type") {
			return false
		}
		return true
	}
}

func (s *Server) dialPeer(address string) {
	if s.isPeerBanned(address) {
		return
	}
	conn, err := net.DialTimeout("tcp", address, 4*time.Second)
	if err != nil {
		log.Printf("peer dial %s failed: %v", address, err)
		return
	}

	c := &Conn{conn: conn, enc: json.NewEncoder(conn)}
	reader := scannerReader(conn)

	sig, err := signServerIdentity(s.ownerPriv, s.id)
	if err != nil {
		_ = conn.Close()
		return
	}
	if err := c.Send(Packet{Type: "hello", Role: "server", ID: s.id, PubKey: s.ownerPubKeyB64, Sig: sig, Listen: s.advertiseAddr, MaxMsgBytes: s.maxMessageBytes, MaxMsgsPerSec: s.maxMsgsPerSec, Burst: s.burstMessages, Caps: s.localCaps()}); err != nil {
		_ = conn.Close()
		return
	}

	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var response Packet
	if err := s.readPacket(reader, nil, &response); err != nil {
		_ = conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	if response.Type == "error" {
		log.Printf("peer %s rejected connection: %s", address, response.Body)
		_ = conn.Close()
		return
	}
	if response.Type != "ok" || response.ID == "" || !verifyServerIdentity(response.ID, response.PubKey, response.Sig) {
		log.Printf("peer %s invalid identity proof", address)
		_ = conn.Close()
		return
	}
	if response.Listen != "" {
		s.addKnownAddr(response.Listen)
	}

	s.handlePeer(response.ID, address, c, reader, newRateLimiter(s.maxMsgsPerSec, s.burstMessages), response.MaxMsgBytes, response.MaxMsgsPerSec, response.Burst, response.Caps)
}

func scannerReader(conn net.Conn) *bufio.Reader {
	return bufio.NewReaderSize(conn, 64*1024)
}

func (s *Server) serveConn(conn net.Conn) {
	reader := scannerReader(conn)
	encConn := &Conn{conn: conn, enc: json.NewEncoder(conn)}
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	var hello Packet
	if err := s.readPacket(reader, nil, &hello); err != nil {
		_ = conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	if hello.Type != "hello" {
		_ = encConn.Send(Packet{Type: "error", Body: "first packet must be hello"})
		_ = conn.Close()
		return
	}

	switch hello.Role {
	case "user":
		loginID, err := s.authenticateUser(encConn, reader, hello.PubKey)
		if err != nil {
			_ = encConn.Send(Packet{Type: "error", Body: "auth failed: " + err.Error()})
			_ = conn.Close()
			return
		}
		if !s.isClientAllowed(loginID) {
			_ = encConn.Send(Packet{Type: "error", Body: "client access not allowed by this server"})
			_ = conn.Close()
			return
		}
		s.handleUser(loginID, encConn, reader, newRateLimiter(s.maxMsgsPerSec, s.burstMessages))
	case "server":
		peerID := strings.TrimSpace(hello.ID)
		if peerID == "" {
			_ = encConn.Send(Packet{Type: "error", Body: "server id required"})
			_ = conn.Close()
			return
		}
		peerListen := normalizeAddr(hello.Listen)
		remoteAddr := normalizeAddr(conn.RemoteAddr().String())
		if peerListen != "" {
			remoteAddr = peerListen
		}
		if s.isPeerBanned(remoteAddr) {
			_ = encConn.Send(Packet{Type: "error", Body: "peer temporarily banned"})
			_ = conn.Close()
			return
		}
		if !verifyServerIdentity(peerID, hello.PubKey, hello.Sig) {
			_ = encConn.Send(Packet{Type: "error", Body: "invalid server identity proof"})
			_ = conn.Close()
			return
		}
		sig, err := signServerIdentity(s.ownerPriv, s.id)
		if err != nil {
			_ = encConn.Send(Packet{Type: "error", Body: "server identity unavailable"})
			_ = conn.Close()
			return
		}
		_ = encConn.Send(Packet{Type: "ok", ID: s.id, Body: "peer accepted", PubKey: s.ownerPubKeyB64, Sig: sig, Listen: s.advertiseAddr, MaxMsgBytes: s.maxMessageBytes, MaxMsgsPerSec: s.maxMsgsPerSec, Burst: s.burstMessages, Caps: s.localCaps()})
		if peerListen != "" {
			s.addKnownAddr(peerListen)
		}
		s.handlePeer(peerID, remoteAddr, encConn, reader, newRateLimiter(s.maxMsgsPerSec, s.burstMessages), hello.MaxMsgBytes, hello.MaxMsgsPerSec, hello.Burst, hello.Caps)
	default:
		_ = encConn.Send(Packet{Type: "error", Body: "unknown role"})
		_ = conn.Close()
	}
}

func main() {
	listenAddr := flag.String("listen", ":9000", "tcp address to listen on")
	advertiseAddr := flag.String("advertise", "", "public host:port to share with peers")
	ownerClaim := flag.String("owner", "", "owner login id (sha256(pubkey))")
	localSID := flag.String("sid", "default", "owner-scoped local server id")
	ownerKeyPath := flag.String("key", "", "owner private key file")
	peersCSV := flag.String("peers", "", "comma-separated seed peer addresses (host:port)")
	maxPeers := flag.Int("max-peers", 32, "maximum concurrent peer sessions")
	maxMsgBytes := flag.Int("max-msg-bytes", defaultMaxMessageBytes, "maximum accepted packet size in bytes")
	maxMsgsPerSec := flag.Int("max-msgs-per-sec", defaultMaxMsgsPerSec, "maximum accepted packets per second per connection")
	burstMessages := flag.Int("burst", defaultBurstMessages, "burst packet allowance per connection")
	maxSeen := flag.Int("max-seen", defaultMaxSeenEntries, "maximum dedupe IDs kept in memory")
	maxKnownAddrs := flag.Int("max-known-addrs", defaultMaxKnownAddrs, "maximum known peer addresses kept in memory")
	knownAddrTTL := flag.Duration("known-addr-ttl", defaultKnownAddrTTL, "known peer address TTL")
	relayEnabled := flag.Bool("relay", true, "relay messages across peer network")
	clientMode := flag.String("client-mode", clientModePublic, "client access mode: public|private|disabled")
	clientAllowCSV := flag.String("client-allow", "", "comma-separated login_id allowlist for client-mode=private")
	flag.Parse()

	if strings.TrimSpace(*ownerKeyPath) == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("unable to resolve home directory: %v", err)
		}
		*ownerKeyPath = filepath.Join(home, ".goaccord", "server_owner_key.json")
	}

	ownerPriv, err := loadOrCreateKey(*ownerKeyPath)
	if err != nil {
		log.Fatalf("owner key load/create failed: %v", err)
	}
	ownerPub := ownerPriv.Public().(ed25519.PublicKey)
	ownerLoginID := loginIDForPubKey(ownerPub)
	if strings.TrimSpace(*ownerClaim) != "" && strings.TrimSpace(*ownerClaim) != ownerLoginID {
		log.Fatalf("-owner mismatch: provided=%s derived=%s", strings.TrimSpace(*ownerClaim), ownerLoginID)
	}

	serverID, err := composeServerID(ownerLoginID, *localSID)
	if err != nil {
		log.Fatalf("invalid server identity: %v", err)
	}

	s := NewServer(
		serverID,
		base64.StdEncoding.EncodeToString(ownerPub),
		ownerPriv,
		*advertiseAddr,
		*maxPeers,
		*maxMsgBytes,
		*maxMsgsPerSec,
		*burstMessages,
		*maxSeen,
		*maxKnownAddrs,
		*knownAddrTTL,
	)

	s.relayEnabled = *relayEnabled
	mode := strings.ToLower(strings.TrimSpace(*clientMode))
	switch mode {
	case clientModePublic, clientModePrivate, clientModeDisabled:
		s.clientMode = mode
	default:
		log.Fatalf("invalid -client-mode: %s", *clientMode)
	}
	if s.clientMode == clientModePrivate {
		for _, id := range strings.Split(*clientAllowCSV, ",") {
			id = strings.TrimSpace(id)
			if id == "" {
				continue
			}
			s.clientAllow[id] = struct{}{}
		}
		if len(s.clientAllow) == 0 {
			log.Fatalf("client-mode=private requires -client-allow")
		}
	}
	go s.cleanupSeen(10 * time.Minute)
	go s.peerManager()

	if strings.TrimSpace(*peersCSV) != "" {
		for _, peer := range strings.Split(*peersCSV, ",") {
			peer = strings.TrimSpace(peer)
			if peer == "" {
				continue
			}
			s.addKnownAddr(peer)
		}
	}

	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("listen error: %v", err)
	}
	log.Printf("server %q listening on %s", s.id, *listenAddr)
	log.Printf("owner login_id %q (key: %s)", ownerLoginID, *ownerKeyPath)
	log.Printf("limits: max-msg-bytes=%d max-msgs-per-sec=%d burst=%d max-seen=%d max-known-addrs=%d known-addr-ttl=%s", s.maxMessageBytes, s.maxMsgsPerSec, s.burstMessages, s.maxSeenEntries, s.maxKnownAddrs, s.knownAddrTTL)
	if s.advertiseAddr != "" {
		log.Printf("advertising as %s", s.advertiseAddr)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go s.serveConn(conn)
	}
}
