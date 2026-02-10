package main

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type storedMessage struct {
	ID      string
	From    string
	To      string
	Body    string
	Group   string
	Channel string
	Origin  string
	PubKey  string
	Sig     string
}

type sqliteStore struct {
	db             *sql.DB
	maxPendingUser int
}

func openSQLiteStore(path string, serverID string, ownerID string, maxPendingUser int) (*sqliteStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("sqlite path is required")
	}
	if err := ensureDir(path); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	store := &sqliteStore{db: db, maxPendingUser: maxPendingUser}
	if store.maxPendingUser <= 0 {
		store.maxPendingUser = 500
	}
	if err := store.initSchema(serverID, ownerID); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := store.touchServer(serverID, ownerID); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func ensureDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		return nil
	}
	return mkdirAll700(dir)
}

func mkdirAll700(path string) error {
	return os.MkdirAll(path, 0o700)
}

func (s *sqliteStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *sqliteStore) initSchema(serverID string, ownerID string) error {
	schema := []string{
		`PRAGMA journal_mode=WAL;`,
		`CREATE TABLE IF NOT EXISTS meta (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS hosted_users (
			login_id TEXT PRIMARY KEY,
			created_at INTEGER NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS pending_messages (
			seq INTEGER PRIMARY KEY AUTOINCREMENT,
			to_id TEXT NOT NULL,
			msg_id TEXT NOT NULL,
			from_id TEXT NOT NULL,
			body TEXT NOT NULL,
			group_name TEXT,
			channel_name TEXT,
			origin TEXT,
			pub_key TEXT,
			sig TEXT,
			created_at INTEGER NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_pending_to_seq ON pending_messages(to_id, seq);`,
		`CREATE TABLE IF NOT EXISTS groups_meta (
			group_name TEXT PRIMARY KEY,
			creator_login_id TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS channels_meta (
			group_name TEXT NOT NULL,
			channel_name TEXT NOT NULL,
			creator_login_id TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			PRIMARY KEY(group_name, channel_name)
		);`,
		`CREATE TABLE IF NOT EXISTS servers_meta (
			server_id TEXT PRIMARY KEY,
			owner_login_id TEXT NOT NULL,
			seen_at INTEGER NOT NULL
		);`,
	}
	for _, stmt := range schema {
		if _, err := s.db.Exec(stmt); err != nil {
			return err
		}
	}

	if err := s.setMetaIfMissing("server_id", serverID); err != nil {
		return err
	}
	if err := s.setMetaIfMissing("owner_id", ownerID); err != nil {
		return err
	}

	gotServerID, err := s.getMeta("server_id")
	if err != nil {
		return err
	}
	if gotServerID != serverID {
		return fmt.Errorf("sqlite db belongs to server_id=%s, expected=%s", gotServerID, serverID)
	}
	gotOwnerID, err := s.getMeta("owner_id")
	if err != nil {
		return err
	}
	if gotOwnerID != ownerID {
		return fmt.Errorf("sqlite db belongs to owner_id=%s, expected=%s", gotOwnerID, ownerID)
	}
	return nil
}

func (s *sqliteStore) setMetaIfMissing(key string, value string) error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO meta(key, value) VALUES(?, ?)`, key, value)
	return err
}

func (s *sqliteStore) getMeta(key string) (string, error) {
	var value string
	err := s.db.QueryRow(`SELECT value FROM meta WHERE key = ?`, key).Scan(&value)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("meta key %s missing", key)
		}
		return "", err
	}
	return value, nil
}

func (s *sqliteStore) touchServer(serverID string, ownerID string) error {
	if strings.TrimSpace(serverID) == "" || strings.TrimSpace(ownerID) == "" {
		return nil
	}
	now := time.Now().Unix()
	_, err := s.db.Exec(`
		INSERT INTO servers_meta(server_id, owner_login_id, seen_at)
		VALUES(?, ?, ?)
		ON CONFLICT(server_id) DO UPDATE SET
			owner_login_id = excluded.owner_login_id,
			seen_at = excluded.seen_at
	`, serverID, ownerID, now)
	return err
}

func (s *sqliteStore) addHostedUser(loginID string) error {
	if strings.TrimSpace(loginID) == "" {
		return nil
	}
	_, err := s.db.Exec(`INSERT OR IGNORE INTO hosted_users(login_id, created_at) VALUES(?, ?)`, loginID, time.Now().Unix())
	return err
}

func (s *sqliteStore) isHostedUser(loginID string) (bool, error) {
	var one int
	err := s.db.QueryRow(`SELECT 1 FROM hosted_users WHERE login_id = ?`, loginID).Scan(&one)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (s *sqliteStore) rememberGroup(group string, creator string) error {
	group = strings.TrimSpace(group)
	if group == "" {
		return nil
	}
	now := time.Now().Unix()
	_, err := s.db.Exec(`
		INSERT INTO groups_meta(group_name, creator_login_id, created_at, updated_at)
		VALUES(?, ?, ?, ?)
		ON CONFLICT(group_name) DO UPDATE SET
			updated_at = excluded.updated_at
	`, group, creator, now, now)
	return err
}

func (s *sqliteStore) rememberChannel(group string, channel string, creator string) error {
	group = strings.TrimSpace(group)
	channel = strings.TrimSpace(channel)
	if group == "" || channel == "" {
		return nil
	}
	now := time.Now().Unix()
	_, err := s.db.Exec(`
		INSERT INTO channels_meta(group_name, channel_name, creator_login_id, created_at, updated_at)
		VALUES(?, ?, ?, ?, ?)
		ON CONFLICT(group_name, channel_name) DO UPDATE SET
			updated_at = excluded.updated_at
	`, group, channel, creator, now, now)
	return err
}

func (s *sqliteStore) queueMessageForUser(toID string, msg storedMessage) error {
	toID = strings.TrimSpace(toID)
	if toID == "" {
		return nil
	}
	hosted, err := s.isHostedUser(toID)
	if err != nil {
		return err
	}
	if !hosted {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.Exec(`
		INSERT INTO pending_messages(to_id, msg_id, from_id, body, group_name, channel_name, origin, pub_key, sig, created_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, toID, msg.ID, msg.From, msg.Body, msg.Group, msg.Channel, msg.Origin, msg.PubKey, msg.Sig, time.Now().Unix())
	if err != nil {
		return err
	}

	var count int
	if err := tx.QueryRow(`SELECT COUNT(1) FROM pending_messages WHERE to_id = ?`, toID).Scan(&count); err != nil {
		return err
	}
	over := count - s.maxPendingUser
	if over > 0 {
		_, err = tx.Exec(`
			DELETE FROM pending_messages
			WHERE seq IN (
				SELECT seq FROM pending_messages WHERE to_id = ? ORDER BY seq ASC LIMIT ?
			)
		`, toID, over)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *sqliteStore) popPendingForUser(loginID string, limit int) ([]storedMessage, error) {
	if limit <= 0 {
		limit = 500
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.Query(`
		SELECT seq, msg_id, from_id, to_id, body, group_name, channel_name, origin, pub_key, sig
		FROM pending_messages
		WHERE to_id = ?
		ORDER BY seq ASC
		LIMIT ?
	`, loginID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type rowMsg struct {
		seq int64
		msg storedMessage
	}
	buf := make([]rowMsg, 0, limit)
	for rows.Next() {
		var r rowMsg
		if err := rows.Scan(&r.seq, &r.msg.ID, &r.msg.From, &r.msg.To, &r.msg.Body, &r.msg.Group, &r.msg.Channel, &r.msg.Origin, &r.msg.PubKey, &r.msg.Sig); err != nil {
			return nil, err
		}
		buf = append(buf, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(buf) == 0 {
		return nil, tx.Commit()
	}

	seqs := make([]int64, 0, len(buf))
	out := make([]storedMessage, 0, len(buf))
	for _, r := range buf {
		seqs = append(seqs, r.seq)
		out = append(out, r.msg)
	}

	q := `DELETE FROM pending_messages WHERE seq IN (` + placeholders(len(seqs)) + `)`
	args := make([]any, 0, len(seqs))
	for _, seq := range seqs {
		args = append(args, seq)
	}
	if _, err := tx.Exec(q, args...); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	parts := make([]string, n)
	for i := range parts {
		parts[i] = "?"
	}
	return strings.Join(parts, ",")
}
