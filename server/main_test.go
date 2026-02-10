package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"
)

type testClient struct {
	conn    net.Conn
	enc     *json.Encoder
	dec     *json.Decoder
	priv    ed25519.PrivateKey
	pubB64  string
	loginID string
	counter uint64
}

func signTestMessage(priv ed25519.PrivateKey, id, from, to, body string) (string, error) {
	msg, err := json.Marshal(signedAction{Type: "send", ID: id, From: from, To: to, Body: body})
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, msg)
	return base64.StdEncoding.EncodeToString(sig), nil
}

func startTestServer(t *testing.T, localSID, advertise string, seedAddrs []string) (string, *Server, func()) {
	t.Helper()

	ownerPub, ownerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("owner key generation failed: %v", err)
	}
	ownerLoginID := loginIDForPubKey(ownerPub)
	id, err := composeServerID(ownerLoginID, localSID)
	if err != nil {
		t.Fatalf("composeServerID failed: %v", err)
	}

	s := NewServer(id, base64.StdEncoding.EncodeToString(ownerPub), ownerPriv, advertise, 16)
	for _, seed := range seedAddrs {
		s.addKnownAddr(seed)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serveConn(conn)
		}
	}()
	go s.peerManager()

	stop := func() {
		_ = ln.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("server did not stop")
		}
	}

	return ln.Addr().String(), s, stop
}

func newTestClient(t *testing.T, addr string) *testClient {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}

	c := &testClient{
		conn:   conn,
		enc:    json.NewEncoder(conn),
		dec:    json.NewDecoder(conn),
		priv:   priv,
		pubB64: pubB64,
	}

	if err := c.enc.Encode(Packet{Type: "hello", Role: "user", PubKey: pubB64}); err != nil {
		t.Fatalf("hello send failed: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var challenge Packet
	if err := c.dec.Decode(&challenge); err != nil {
		t.Fatalf("challenge read failed: %v", err)
	}
	if challenge.Type != "challenge" || challenge.Nonce == "" {
		t.Fatalf("unexpected challenge: %+v", challenge)
	}

	sig := ed25519.Sign(priv, []byte("login:"+challenge.Nonce))
	if err := c.enc.Encode(Packet{Type: "auth", PubKey: pubB64, Sig: base64.StdEncoding.EncodeToString(sig)}); err != nil {
		t.Fatalf("auth send failed: %v", err)
	}

	var ok Packet
	if err := c.dec.Decode(&ok); err != nil {
		t.Fatalf("auth response read failed: %v", err)
	}
	_ = conn.SetReadDeadline(time.Time{})

	if ok.Type != "ok" || ok.ID == "" {
		t.Fatalf("unexpected auth response: %+v", ok)
	}
	if want := loginIDForPubKey(pub); ok.ID != want {
		t.Fatalf("login id mismatch: got=%s want=%s", ok.ID, want)
	}
	c.loginID = ok.ID

	return c
}

func (c *testClient) close() {
	_ = c.conn.Close()
}

func (c *testClient) send(t *testing.T, to, body string) {
	t.Helper()

	c.counter++
	id := fmt.Sprintf("test-%d", c.counter)
	sig, err := signTestMessage(c.priv, id, c.loginID, to, body)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	if err := c.enc.Encode(Packet{
		Type:   "send",
		ID:     id,
		From:   c.loginID,
		To:     to,
		Body:   body,
		PubKey: c.pubB64,
		Sig:    sig,
	}); err != nil {
		t.Fatalf("send failed: %v", err)
	}
}

func (c *testClient) recv(t *testing.T, timeout time.Duration) Packet {
	t.Helper()

	_ = c.conn.SetReadDeadline(time.Now().Add(timeout))
	defer func() { _ = c.conn.SetReadDeadline(time.Time{}) }()

	var p Packet
	if err := c.dec.Decode(&p); err != nil {
		t.Fatalf("recv failed: %v", err)
	}
	return p
}

func TestMessageDeliveryBetweenClients(t *testing.T) {
	addr, _, stop := startTestServer(t, "s1", "", nil)
	defer stop()

	alice := newTestClient(t, addr)
	defer alice.close()
	bob := newTestClient(t, addr)
	defer bob.close()

	const body = "hello from alice"
	alice.send(t, bob.loginID, body)

	p := bob.recv(t, 2*time.Second)
	if p.Type != "deliver" {
		t.Fatalf("expected deliver, got: %+v", p)
	}
	if p.From != alice.loginID {
		t.Fatalf("unexpected from: got=%s want=%s", p.From, alice.loginID)
	}
	if p.To != bob.loginID {
		t.Fatalf("unexpected to: got=%s want=%s", p.To, bob.loginID)
	}
	if p.Body != body {
		t.Fatalf("unexpected body: got=%q want=%q", p.Body, body)
	}
}

func TestMessageRelayAcrossPeers(t *testing.T) {
	addrA, srvA, stopA := startTestServer(t, "s1", "", nil)
	defer stopA()
	addrB, _, stopB := startTestServer(t, "s1", "", []string{addrA})
	defer stopB()

	srvA.addKnownAddr(addrB)
	go srvA.dialPeer(addrB)

	alice := newTestClient(t, addrA)
	defer alice.close()
	bob := newTestClient(t, addrB)
	defer bob.close()

	const body = "hello over peer link"
	alice.send(t, bob.loginID, body)

	p := bob.recv(t, 3*time.Second)
	if p.Type != "deliver" {
		t.Fatalf("expected deliver, got: %+v", p)
	}
	if p.From != alice.loginID || p.To != bob.loginID || p.Body != body {
		t.Fatalf("unexpected payload: %+v", p)
	}
}
