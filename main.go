package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Packet struct {
	Type   string `json:"type"`
	Role   string `json:"role,omitempty"`
	ID     string `json:"id,omitempty"`
	From   string `json:"from,omitempty"`
	To     string `json:"to,omitempty"`
	Body   string `json:"body,omitempty"`
	Origin string `json:"origin,omitempty"`
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

type Server struct {
	id string

	mu    sync.RWMutex
	users map[string]*Conn
	peers map[string]*Conn
	seen  map[string]time.Time

	counter atomic.Uint64
}

func NewServer(id string) *Server {
	return &Server{
		id:    id,
		users: make(map[string]*Conn),
		peers: make(map[string]*Conn),
		seen:  make(map[string]time.Time),
	}
}

func (s *Server) nextMessageID() string {
	n := s.counter.Add(1)
	return fmt.Sprintf("%s-%d-%d", s.id, time.Now().UnixNano(), n)
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

func (s *Server) addPeer(peerID string, c *Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.peers[peerID]; ok {
		if existing == c {
			return true
		}
		return false
	}
	s.peers[peerID] = c
	return true
}

func (s *Server) removePeer(peerID string, c *Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.peers[peerID]; ok && existing == c {
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
		targets[peerID] = peer
	}
	s.mu.RUnlock()

	for peerID, peer := range targets {
		if err := peer.Send(p); err != nil {
			log.Printf("forward to peer %q failed: %v", peerID, err)
		}
	}
}

func (s *Server) handleUser(name string, c *Conn, first Packet, dec *json.Decoder) {
	if !s.addUser(name, c) {
		_ = c.Send(Packet{Type: "error", Body: "username already connected"})
		_ = c.conn.Close()
		return
	}
	defer func() {
		s.removeUser(name, c)
		_ = c.conn.Close()
		log.Printf("user disconnected: %s", name)
	}()

	_ = c.Send(Packet{Type: "ok", Body: "registered as " + name})
	log.Printf("user connected: %s", name)

	if first.Type != "" && first.Type != "hello" {
		s.handleUserPacket(name, first)
	}

	for {
		var p Packet
		if err := dec.Decode(&p); err != nil {
			if err != io.EOF {
				log.Printf("user %s read error: %v", name, err)
			}
			return
		}
		s.handleUserPacket(name, p)
	}
}

func (s *Server) handleUserPacket(sender string, p Packet) {
	if p.Type != "send" {
		return
	}
	if strings.TrimSpace(p.To) == "" || strings.TrimSpace(p.Body) == "" {
		return
	}

	msg := Packet{
		Type:   "message",
		ID:     s.nextMessageID(),
		From:   sender,
		To:     p.To,
		Body:   p.Body,
		Origin: s.id,
	}

	_ = s.markSeen(msg.ID)
	s.routeMessage(msg, "")
}

func (s *Server) handlePeer(peerID string, c *Conn, first Packet, dec *json.Decoder) {
	if !s.addPeer(peerID, c) {
		_ = c.Send(Packet{Type: "error", Body: "duplicate peer id"})
		_ = c.conn.Close()
		return
	}
	defer func() {
		s.removePeer(peerID, c)
		_ = c.conn.Close()
		log.Printf("peer disconnected: %s", peerID)
	}()

	_ = c.Send(Packet{Type: "ok", Body: "peer linked to " + s.id})
	log.Printf("peer connected: %s", peerID)

	if first.Type == "message" {
		s.handlePeerMessage(peerID, first)
	}

	for {
		var p Packet
		if err := dec.Decode(&p); err != nil {
			if err != io.EOF {
				log.Printf("peer %s read error: %v", peerID, err)
			}
			return
		}
		if p.Type == "message" {
			s.handlePeerMessage(peerID, p)
		}
	}
}

func (s *Server) handlePeerMessage(fromPeer string, p Packet) {
	if p.ID == "" || p.To == "" || p.From == "" {
		return
	}
	if !s.markSeen(p.ID) {
		return
	}
	s.routeMessage(p, fromPeer)
}

func (s *Server) routeMessage(msg Packet, fromPeer string) {
	s.sendToUser(msg.To, Packet{
		Type:   "deliver",
		ID:     msg.ID,
		From:   msg.From,
		To:     msg.To,
		Body:   msg.Body,
		Origin: msg.Origin,
	})
	s.floodToPeers(fromPeer, msg)
}

func (s *Server) dialPeer(address string) {
	for {
		conn, err := net.Dial("tcp", address)
		if err != nil {
			log.Printf("peer dial %s failed: %v", address, err)
			time.Sleep(2 * time.Second)
			continue
		}

		c := &Conn{conn: conn, enc: json.NewEncoder(conn)}
		dec := json.NewDecoder(bufio.NewReader(conn))

		if err := c.Send(Packet{Type: "hello", Role: "server", ID: s.id}); err != nil {
			_ = conn.Close()
			time.Sleep(2 * time.Second)
			continue
		}

		var response Packet
		if err := dec.Decode(&response); err != nil {
			_ = conn.Close()
			time.Sleep(2 * time.Second)
			continue
		}

		if response.Type == "error" {
			log.Printf("peer %s rejected connection: %s", address, response.Body)
			_ = conn.Close()
			time.Sleep(3 * time.Second)
			continue
		}

		peerID := response.ID
		if peerID == "" {
			peerID = address
		}

		s.handlePeer(peerID, c, Packet{}, dec)
		time.Sleep(2 * time.Second)
	}
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
		name := strings.TrimSpace(hello.ID)
		if name == "" {
			_ = encConn.Send(Packet{Type: "error", Body: "user id required"})
			_ = conn.Close()
			return
		}
		s.handleUser(name, encConn, Packet{}, dec)
	case "server":
		peerID := strings.TrimSpace(hello.ID)
		if peerID == "" {
			_ = encConn.Send(Packet{Type: "error", Body: "server id required"})
			_ = conn.Close()
			return
		}
		_ = encConn.Send(Packet{Type: "ok", ID: s.id, Body: "peer accepted"})
		s.handlePeer(peerID, encConn, Packet{}, dec)
	default:
		_ = encConn.Send(Packet{Type: "error", Body: "unknown role"})
		_ = conn.Close()
	}
}

func main() {
	listenAddr := flag.String("listen", ":9000", "tcp address to listen on")
	serverID := flag.String("id", "", "unique server id")
	peersCSV := flag.String("peers", "", "comma-separated peer addresses (host:port)")
	flag.Parse()

	if *serverID == "" {
		host, _ := os.Hostname()
		*serverID = host
	}

	s := NewServer(*serverID)
	go s.cleanupSeen(10 * time.Minute)

	if strings.TrimSpace(*peersCSV) != "" {
		for _, peer := range strings.Split(*peersCSV, ",") {
			peer = strings.TrimSpace(peer)
			if peer == "" {
				continue
			}
			go s.dialPeer(peer)
		}
	}

	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("listen error: %v", err)
	}
	log.Printf("server %q listening on %s", s.id, *listenAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go s.serveConn(conn)
	}
}
