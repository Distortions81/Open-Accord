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
	Type   string `json:"type"`
	Role   string `json:"role,omitempty"`
	ID     string `json:"id,omitempty"`
	From   string `json:"from,omitempty"`
	To     string `json:"to,omitempty"`
	Body   string `json:"body,omitempty"`
	Origin string `json:"origin,omitempty"`
	Nonce  string `json:"nonce,omitempty"`
	PubKey string `json:"pub_key,omitempty"`
	Sig    string `json:"sig,omitempty"`
}

type signedMessage struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	From string `json:"from"`
	To   string `json:"to,omitempty"`
	Body string `json:"body,omitempty"`
}

type keyFile struct {
	PrivateKey string `json:"private_key"`
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

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	_ = pub

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

func signMessage(priv ed25519.PrivateKey, id, from, to, body string) (string, error) {
	msg, err := json.Marshal(signedMessage{Type: "send", ID: id, From: from, To: to, Body: body})
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, msg)
	return base64.StdEncoding.EncodeToString(sig), nil
}

func nextMessageID(loginID string, counter *atomic.Uint64) string {
	n := counter.Add(1)
	return fmt.Sprintf("%s-%d-%d", loginID[:12], time.Now().UnixNano(), n)
}

func main() {
	addr := flag.String("addr", "127.0.0.1:9000", "server address")
	keyPath := flag.String("key", "", "private key file path")
	defaultTo := flag.String("to", "", "default recipient for interactive mode")
	oneshootMsg := flag.String("msg", "", "send one message and exit")
	flag.Parse()

	if strings.TrimSpace(*keyPath) == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("unable to resolve home directory: %v", err)
		}
		*keyPath = filepath.Join(home, ".goaccord", "ed25519_key.json")
	}

	priv, err := loadOrCreateKey(*keyPath)
	if err != nil {
		log.Fatalf("key load/create failed: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	conn, err := net.Dial("tcp", *addr)
	if err != nil {
		log.Fatalf("connect failed: %v", err)
	}
	defer conn.Close()

	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)

	if err := enc.Encode(Packet{Type: "hello", Role: "user", PubKey: pubB64}); err != nil {
		log.Fatalf("handshake send failed: %v", err)
	}

	var challenge Packet
	if err := dec.Decode(&challenge); err != nil {
		log.Fatalf("challenge read failed: %v", err)
	}
	if challenge.Type == "error" {
		log.Fatalf("server rejected: %s", challenge.Body)
	}
	if challenge.Type != "challenge" || strings.TrimSpace(challenge.Nonce) == "" {
		log.Fatalf("invalid challenge packet: %+v", challenge)
	}

	loginSig := ed25519.Sign(priv, []byte("login:"+challenge.Nonce))
	if err := enc.Encode(Packet{Type: "auth", PubKey: pubB64, Sig: base64.StdEncoding.EncodeToString(loginSig)}); err != nil {
		log.Fatalf("auth send failed: %v", err)
	}

	var helloResp Packet
	if err := dec.Decode(&helloResp); err != nil {
		log.Fatalf("auth response failed: %v", err)
	}
	if helloResp.Type == "error" {
		log.Fatalf("auth failed: %s", helloResp.Body)
	}
	if helloResp.Type != "ok" || strings.TrimSpace(helloResp.ID) == "" {
		log.Fatalf("invalid auth response: %+v", helloResp)
	}

	loginID := helloResp.ID
	if expected := loginIDForPubKey(pub); expected != loginID {
		log.Fatalf("login id mismatch from server")
	}

	fmt.Printf("connected to %s\n", *addr)
	fmt.Printf("login_id: %s\n", loginID)
	fmt.Printf("key file: %s\n", *keyPath)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			var p Packet
			if err := dec.Decode(&p); err != nil {
				fmt.Println("connection closed")
				return
			}
			switch p.Type {
			case "deliver":
				fmt.Printf("[%s -> %s] %s\n", p.From, p.To, p.Body)
			case "error":
				fmt.Printf("server error: %s\n", p.Body)
			default:
				fmt.Printf("server: %+v\n", p)
			}
		}
	}()

	var msgCounter atomic.Uint64
	if strings.TrimSpace(*oneshootMsg) != "" {
		if strings.TrimSpace(*defaultTo) == "" {
			log.Fatal("-to is required with -msg")
		}
		id := nextMessageID(loginID, &msgCounter)
		sig, err := signMessage(priv, id, loginID, *defaultTo, *oneshootMsg)
		if err != nil {
			log.Fatalf("sign failed: %v", err)
		}
		if err := enc.Encode(Packet{Type: "send", ID: id, From: loginID, To: *defaultTo, Body: *oneshootMsg, PubKey: pubB64, Sig: sig}); err != nil {
			log.Fatalf("send failed: %v", err)
		}
		return
	}

	fmt.Println("interactive mode")
	fmt.Println("type: @recipient_login_id message")
	if strings.TrimSpace(*defaultTo) != "" {
		fmt.Printf("default recipient: %s (plain text sends there)\n", *defaultTo)
	}
	fmt.Println("type /quit to exit")

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if line == "/quit" {
			break
		}

		to := strings.TrimSpace(*defaultTo)
		body := line
		if strings.HasPrefix(line, "@") {
			parts := strings.SplitN(line[1:], " ", 2)
			if len(parts) < 2 {
				fmt.Println("format: @recipient_login_id message")
				continue
			}
			to = strings.TrimSpace(parts[0])
			body = strings.TrimSpace(parts[1])
		}

		if to == "" {
			fmt.Println("no recipient set; use @recipient_login_id message or -to")
			continue
		}

		id := nextMessageID(loginID, &msgCounter)
		sig, err := signMessage(priv, id, loginID, to, body)
		if err != nil {
			fmt.Printf("sign error: %v\n", err)
			continue
		}
		if err := enc.Encode(Packet{Type: "send", ID: id, From: loginID, To: to, Body: body, PubKey: pubB64, Sig: sig}); err != nil {
			fmt.Printf("send error: %v\n", err)
			break
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("stdin error: %v\n", err)
	}
	_ = conn.Close()
	wg.Wait()
}
