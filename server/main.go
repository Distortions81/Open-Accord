package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	listenAddr := flag.String("listen", ":9000", "tcp address to listen on")
	advertiseAddr := flag.String("advertise", "", "public host:port to share with peers")
	ownerClaim := flag.String("owner", "", "owner login id (sha256(pubkey))")
	localSID := flag.String("sid", "default", "owner-scoped local server id")
	ownerKeyPath := flag.String("key", "", "owner private key file")
	peersCSV := flag.String("peers", "", "comma-separated seed peer addresses (host:port)")
	maxPeers := flag.Int("max-peers", 32, "maximum concurrent peer sessions")
	maxMsgBytes := flag.Int("max-msg-bytes", defaultMaxMessageBytes, "maximum accepted packet size in bytes")
	maxUncompressedBytes := flag.Int("max-uncompressed-bytes", defaultMaxUncompressedBytes, "maximum accepted uncompressed text body size in bytes")
	maxExpandRatio := flag.Int("max-expand-ratio", defaultMaxExpandRatio, "maximum decoded/compressed size ratio for compressed bodies")
	maxMsgsPerSec := flag.Int("max-msgs-per-sec", defaultMaxMsgsPerSec, "maximum accepted packets per second per connection")
	burstMessages := flag.Int("burst", defaultBurstMessages, "burst packet allowance per connection")
	maxSeen := flag.Int("max-seen", defaultMaxSeenEntries, "maximum dedupe IDs kept in memory")
	maxKnownAddrs := flag.Int("max-known-addrs", defaultMaxKnownAddrs, "maximum known peer addresses kept in memory")
	knownAddrTTL := flag.Duration("known-addr-ttl", defaultKnownAddrTTL, "known peer address TTL")
	relayEnabled := flag.Bool("relay", true, "relay messages across peer network")
	clientMode := flag.String("client-mode", clientModePublic, "client access mode: public|private|disabled")
	clientAllowCSV := flag.String("client-allow", "", "comma-separated login_id allowlist for client-mode=private")
	persistenceMode := flag.String("persistence-mode", persistenceModeLive, "storage mode: live|persist")
	persistenceDB := flag.String("persistence-db", "", "sqlite database path (used when persistence-mode=persist)")
	persistAutoHost := flag.Bool("persist-auto-host", true, "auto-register authenticated users as hosted users in persist mode")
	maxPendingMsgs := flag.Int("max-pending-msgs", 500, "maximum queued offline messages per hosted user in persist mode")
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

	s.maxUncompressedBytes = *maxUncompressedBytes
	s.maxExpandRatio = *maxExpandRatio
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

	s.persistAutoHost = *persistAutoHost
	s.maxPendingMsgs = *maxPendingMsgs
	pmode := strings.ToLower(strings.TrimSpace(*persistenceMode))
	switch pmode {
	case persistenceModeLive, persistenceModePersist:
		s.persistenceMode = pmode
	default:
		log.Fatalf("invalid -persistence-mode: %s", *persistenceMode)
	}
	if s.persistenceMode == persistenceModePersist {
		dbPath := strings.TrimSpace(*persistenceDB)
		if dbPath == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				log.Fatalf("unable to resolve home directory: %v", err)
			}
			dbPath = filepath.Join(home, ".goaccord", "state", strings.ReplaceAll(s.id, ":", "_")+".sqlite")
		}
		store, err := openSQLiteStore(dbPath, s.id, ownerLoginID, s.maxPendingMsgs)
		if err != nil {
			log.Fatalf("sqlite init failed: %v", err)
		}
		s.store = store
		defer func() {
			if err := store.Close(); err != nil {
				log.Printf("sqlite close error: %v", err)
			}
		}()
		log.Printf("persistence: mode=%s db=%s max-pending-msgs=%d auto-host=%t", s.persistenceMode, dbPath, s.maxPendingMsgs, s.persistAutoHost)
	} else {
		log.Printf("persistence: mode=%s", s.persistenceMode)
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
	log.Printf("limits: max-msg-bytes=%d max-uncompressed-bytes=%d max-expand-ratio=%d max-msgs-per-sec=%d burst=%d max-seen=%d max-known-addrs=%d known-addr-ttl=%s", s.maxMessageBytes, s.maxUncompressedBytes, s.maxExpandRatio, s.maxMsgsPerSec, s.burstMessages, s.maxSeenEntries, s.maxKnownAddrs, s.knownAddrTTL)
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
