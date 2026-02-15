package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func buildSignedFriendKeyBodyForTUI(t *testing.T, priv ed25519.PrivateKey, e2eePub string, ts int64, nonce string) string {
	t.Helper()
	pub := priv.Public().(ed25519.PublicKey)
	sig := ed25519.Sign(priv, friendKeyMessage(e2eePub, ts, nonce))
	payload := friendKeyPayload{
		E2EEPub: e2eePub,
		PubKey:  base64.StdEncoding.EncodeToString(pub),
		Sig:     base64.StdEncoding.EncodeToString(sig),
		TS:      ts,
		Nonce:   nonce,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	return string(b)
}

func TestTUIParseFriendKeyRejectsIdentityMismatch(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	body := buildSignedFriendKeyBodyForTUI(t, priv, "test-e2ee-pub", time.Now().UnixMilli(), "nonce-mismatch")
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("other keygen failed: %v", err)
	}

	_, present, err := parseFriendKey(body, loginIDForPubKey(otherPub))
	if !present {
		t.Fatalf("expected payload to be present")
	}
	if err == nil {
		t.Fatalf("expected identity mismatch error")
	}
}

func TestTUIParseFriendKeyRejectsTooFarFutureTimestamp(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	from := loginIDForPubKey(pub)
	body := buildSignedFriendKeyBodyForTUI(t, priv, "test-e2ee-pub", time.Now().Add(6*time.Minute).UnixMilli(), "nonce-future")

	_, present, err := parseFriendKey(body, from)
	if !present {
		t.Fatalf("expected payload to be present")
	}
	if err == nil {
		t.Fatalf("expected future timestamp rejection")
	}
}

func TestTUIParseFriendKeyRejectsOldTimestamp(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	from := loginIDForPubKey(pub)
	body := buildSignedFriendKeyBodyForTUI(t, priv, "test-e2ee-pub", time.Now().Add(-friendKeyMaxAge-time.Minute).UnixMilli(), "nonce-old")

	_, present, err := parseFriendKey(body, from)
	if !present {
		t.Fatalf("expected payload to be present")
	}
	if err == nil {
		t.Fatalf("expected old timestamp rejection")
	}
}

func TestTUIConsumeFriendKeyRejectsReplayNonce(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	from := loginIDForPubKey(pub)
	body := buildSignedFriendKeyBodyForTUI(t, priv, "test-e2ee-pub", time.Now().UnixMilli(), "nonce-replay")

	m := &model{
		friendKeyNonces: make(map[string]map[string]int64),
	}
	if _, err := m.consumeFriendKey(from, body); err != nil {
		t.Fatalf("first consume failed: %v", err)
	}
	if _, err := m.consumeFriendKey(from, body); err == nil {
		t.Fatalf("expected replay rejection")
	}
}

func TestTUIApplyFocusClearsUnreadForTarget(t *testing.T) {
	dmID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	chKey := "dev/general"
	m := &model{
		dmUnread:      map[string]int{dmID: 3},
		channelUnread: map[string]int{chKey: 4},
	}

	m.applyFocus(panelTarget{mode: panelDirect, direct: dmID})
	if got := m.dmUnread[dmID]; got != 0 {
		t.Fatalf("expected dm unread to clear, got %d", got)
	}

	m.applyFocus(panelTarget{mode: panelChannel, channel: chKey})
	if got := m.channelUnread[chKey]; got != 0 {
		t.Fatalf("expected channel unread to clear, got %d", got)
	}
}

func TestTUIUnreadTotalsAndServerAggregation(t *testing.T) {
	m := &model{
		dmUnread: map[string]int{
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": 2,
		},
		channelUnread: map[string]int{
			"dev/general":   3,
			"dev/random":    1,
			"other/general": 5,
		},
	}

	if got := m.serverUnreadCount("dev"); got != 4 {
		t.Fatalf("unexpected dev unread total: got %d want 4", got)
	}
	if got := m.serverUnreadCount("other"); got != 5 {
		t.Fatalf("unexpected other unread total: got %d want 5", got)
	}
	if got := m.totalUnread(); got != 11 {
		t.Fatalf("unexpected total unread: got %d want 11", got)
	}
}
