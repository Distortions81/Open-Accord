package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
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

func main() {
	addr := flag.String("addr", "127.0.0.1:9000", "server address")
	userID := flag.String("id", "", "your user id")
	defaultTo := flag.String("to", "", "default recipient for interactive mode")
	oneshootMsg := flag.String("msg", "", "send one message and exit")
	flag.Parse()

	if strings.TrimSpace(*userID) == "" {
		log.Fatal("-id is required")
	}

	conn, err := net.Dial("tcp", *addr)
	if err != nil {
		log.Fatalf("connect failed: %v", err)
	}
	defer conn.Close()

	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)

	if err := enc.Encode(Packet{Type: "hello", Role: "user", ID: *userID}); err != nil {
		log.Fatalf("handshake send failed: %v", err)
	}

	var helloResp Packet
	if err := dec.Decode(&helloResp); err != nil {
		log.Fatalf("handshake response failed: %v", err)
	}
	if helloResp.Type == "error" {
		log.Fatalf("server rejected: %s", helloResp.Body)
	}
	fmt.Printf("connected as %s to %s\n", *userID, *addr)

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

	if strings.TrimSpace(*oneshootMsg) != "" {
		if strings.TrimSpace(*defaultTo) == "" {
			log.Fatal("-to is required with -msg")
		}
		if err := enc.Encode(Packet{Type: "send", To: *defaultTo, Body: *oneshootMsg}); err != nil {
			log.Fatalf("send failed: %v", err)
		}
		return
	}

	fmt.Println("interactive mode")
	fmt.Println("type: @recipient message")
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
				fmt.Println("format: @recipient message")
				continue
			}
			to = strings.TrimSpace(parts[0])
			body = strings.TrimSpace(parts[1])
		}

		if to == "" {
			fmt.Println("no recipient set; use @recipient message or -to")
			continue
		}

		if err := enc.Encode(Packet{Type: "send", To: to, Body: body}); err != nil {
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
