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

type Packet struct {
	Type   string   `json:"type"`
	Role   string   `json:"role,omitempty"`
	ID     string   `json:"id,omitempty"`
	From   string   `json:"from,omitempty"`
	To     string   `json:"to,omitempty"`
	Body   string   `json:"body,omitempty"`
	Origin string   `json:"origin,omitempty"`
	Nonce  string   `json:"nonce,omitempty"`
	PubKey string   `json:"pub_key,omitempty"`
	Sig    string   `json:"sig,omitempty"`
	Listen string   `json:"listen,omitempty"`
	Addrs  []string `json:"addrs,omitempty"`
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
	conn *Conn
	addr string
}

type Server struct {
	id              string
	ownerPubKeyB64  string
	ownerPriv       ed25519.PrivateKey
	advertiseAddr   string
	maxPeerSessions int

	mu         sync.RWMutex
	users      map[string]*Conn
	peers      map[string]*Peer
	seen       map[string]time.Time
	knownAddrs map[string]time.Time
	dialing    map[string]struct{}

	counter atomic.Uint64
}

func NewServer(id, ownerPubKeyB64 string, ownerPriv ed25519.PrivateKey, advertiseAddr string, maxPeerSessions int) *Server {
	return &Server{
		id:              id,
		ownerPubKeyB64:  ownerPubKeyB64,
		ownerPriv:       ownerPriv,
		advertiseAddr:   normalizeAddr(advertiseAddr),
		maxPeerSessions: maxPeerSessions,
		users:           make(map[string]*Conn),
		peers:           make(map[string]*Peer),
		seen:            make(map[string]time.Time),
		knownAddrs:      make(map[string]time.Time),
		dialing:         make(map[string]struct{}),
	}
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
	return !existed
}

func (s *Server) isConnectedAddr(addr string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, peer := range s.peers {
		if peer.addr == addr {
			return true
		}
	}
	_, dialing := s.dialing[addr]
	return dialing
}

func (s *Server) nextDialCandidate() string {
	s.mu.Lock()
	defer s.mu.Unlock()
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
	s.mu.RLock()
	defer s.mu.RUnlock()
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
	return out
}

func (s *Server) markSeen(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.seen[id]; ok {
		return false
	}
	s.seen[id] = time.Now()
	return true
}

func (s *Server) cleanupSeen(ttl time.Duration) {
	ticker := time.NewTicker(ttl / 2)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-ttl)
		s.mu.Lock()
		for id, t := range s.seen {
			if t.Before(cutoff) {
				delete(s.seen, id)
			}
		}
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

func (s *Server) addPeer(peerID, addr string, c *Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.peers[peerID]; ok {
		if existing.conn == c {
			return true
		}
		return false
	}
	s.peers[peerID] = &Peer{conn: c, addr: addr}
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
	s.mu.RLock()
	targets := make(map[string]*Conn, len(s.peers))
	for peerID, peer := range s.peers {
		if peerID == exceptID {
			continue
		}
		targets[peerID] = peer.conn
	}
	s.mu.RUnlock()

	for peerID, peer := range targets {
		if err := peer.Send(p); err != nil {
			log.Printf("forward to peer %q failed: %v", peerID, err)
		}
	}
}

func (s *Server) sendAddr(c *Conn) {
	_ = c.Send(Packet{Type: "addr", Addrs: s.peerAddrSnapshot(64)})
}

func (s *Server) authenticateUser(c *Conn, dec *json.Decoder, claimedPubKey string) (string, error) {
	nonce := s.nextMessageID()
	if err := c.Send(Packet{Type: "challenge", Nonce: nonce}); err != nil {
		return "", err
	}

	_ = c.conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	defer func() { _ = c.conn.SetReadDeadline(time.Time{}) }()

	var auth Packet
	if err := dec.Decode(&auth); err != nil {
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

func (s *Server) handleUser(loginID string, c *Conn, dec *json.Decoder) {
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
		if err := dec.Decode(&p); err != nil {
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
	s.floodToPeers("", p)
}

func (s *Server) handlePeer(peerID, peerAddr string, c *Conn, dec *json.Decoder) {
	if !s.addPeer(peerID, peerAddr, c) {
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
		if err := dec.Decode(&p); err != nil {
			if err != io.EOF {
				log.Printf("peer %s read error: %v", peerID, err)
			}
			return
		}
		s.handlePeerPacket(peerID, c, p)
	}
}

func (s *Server) handlePeerPacket(fromPeer string, c *Conn, p Packet) {
	switch p.Type {
	case "send":
		if strings.TrimSpace(p.ID) == "" || strings.TrimSpace(p.From) == "" || strings.TrimSpace(p.To) == "" || strings.TrimSpace(p.Body) == "" {
			return
		}
		if !verifyActionSignature(p) {
			return
		}
		if !s.markSeen(p.ID) {
			return
		}
		s.sendToUser(p.To, Packet{Type: "deliver", ID: p.ID, From: p.From, To: p.To, Body: p.Body, Origin: s.id, PubKey: p.PubKey, Sig: p.Sig})
		s.floodToPeers(fromPeer, p)
	case "getaddr":
		s.sendAddr(c)
	case "addr":
		for _, a := range p.Addrs {
			_ = s.addKnownAddr(a)
		}
	}
}

func (s *Server) dialPeer(address string) {
	conn, err := net.DialTimeout("tcp", address, 4*time.Second)
	if err != nil {
		log.Printf("peer dial %s failed: %v", address, err)
		return
	}

	c := &Conn{conn: conn, enc: json.NewEncoder(conn)}
	dec := json.NewDecoder(bufio.NewReader(conn))

	sig, err := signServerIdentity(s.ownerPriv, s.id)
	if err != nil {
		_ = conn.Close()
		return
	}
	if err := c.Send(Packet{Type: "hello", Role: "server", ID: s.id, PubKey: s.ownerPubKeyB64, Sig: sig, Listen: s.advertiseAddr}); err != nil {
		_ = conn.Close()
		return
	}

	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var response Packet
	if err := dec.Decode(&response); err != nil {
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

	s.handlePeer(response.ID, address, c, dec)
}

func scannerReader(conn net.Conn) *bufio.Reader {
	return bufio.NewReaderSize(conn, 64*1024)
}

func (s *Server) serveConn(conn net.Conn) {
	reader := scannerReader(conn)
	dec := json.NewDecoder(reader)
	encConn := &Conn{conn: conn, enc: json.NewEncoder(conn)}

	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	var hello Packet
	if err := dec.Decode(&hello); err != nil {
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
		loginID, err := s.authenticateUser(encConn, dec, hello.PubKey)
		if err != nil {
			_ = encConn.Send(Packet{Type: "error", Body: "auth failed: " + err.Error()})
			_ = conn.Close()
			return
		}
		s.handleUser(loginID, encConn, dec)
	case "server":
		peerID := strings.TrimSpace(hello.ID)
		if peerID == "" {
			_ = encConn.Send(Packet{Type: "error", Body: "server id required"})
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
		_ = encConn.Send(Packet{Type: "ok", ID: s.id, Body: "peer accepted", PubKey: s.ownerPubKeyB64, Sig: sig, Listen: s.advertiseAddr})
		peerListen := normalizeAddr(hello.Listen)
		if peerListen != "" {
			s.addKnownAddr(peerListen)
		}
		remoteAddr := normalizeAddr(conn.RemoteAddr().String())
		if peerListen != "" {
			remoteAddr = peerListen
		}
		s.handlePeer(peerID, remoteAddr, encConn, dec)
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

	s := NewServer(serverID, base64.StdEncoding.EncodeToString(ownerPub), ownerPriv, *advertiseAddr, *maxPeers)
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
