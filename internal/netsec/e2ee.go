package netsec

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	dmEnvelopeVersionV1 = 1
	dmEnvelopeAlgV1     = "x25519-aesgcm"
	dmEnvelopeVersionV2 = 2
	dmEnvelopeAlgV2     = "x25519-aesgcm-multi"
)

type DMEnvelope struct {
	V   int                 `json:"v"`
	Alg string              `json:"alg"`
	SPK string              `json:"spk"`
	N   string              `json:"n"`
	CT  string              `json:"ct"`
	R   []dmRecipientCipher `json:"r,omitempty"`
}

type dmRecipientCipher struct {
	PK string `json:"pk"`
	N  string `json:"n"`
	CT string `json:"ct"`
}

func NewX25519Identity() (*ecdh.PrivateKey, string, error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	return priv, base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

func ParseX25519PrivateKeyB64(v string) (*ecdh.PrivateKey, string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v))
	if err != nil {
		return nil, "", err
	}
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return nil, "", err
	}
	return priv, base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

func EncryptDM(senderPriv *ecdh.PrivateKey, recipientPubB64 string, plaintext string) (string, error) {
	return EncryptDMMulti(senderPriv, []string{recipientPubB64}, plaintext)
}

func EncryptDMMulti(senderPriv *ecdh.PrivateKey, recipientPubB64 []string, plaintext string) (string, error) {
	if senderPriv == nil {
		return "", fmt.Errorf("missing sender e2ee key")
	}
	seen := make(map[string]struct{})
	recipients := make([]dmRecipientCipher, 0, len(recipientPubB64))
	for _, candidate := range recipientPubB64 {
		pkB64 := strings.TrimSpace(candidate)
		if pkB64 == "" {
			continue
		}
		if _, dup := seen[pkB64]; dup {
			continue
		}
		seen[pkB64] = struct{}{}
		recipientPubRaw, err := base64.StdEncoding.DecodeString(pkB64)
		if err != nil {
			return "", fmt.Errorf("invalid recipient e2ee key")
		}
		recipientPub, err := ecdh.X25519().NewPublicKey(recipientPubRaw)
		if err != nil {
			return "", fmt.Errorf("invalid recipient e2ee key")
		}
		shared, err := senderPriv.ECDH(recipientPub)
		if err != nil {
			return "", fmt.Errorf("ecdh failed")
		}
		key := deriveDMKey(shared, senderPriv.PublicKey().Bytes(), recipientPubRaw)
		aesBlock, err := aes.NewCipher(key)
		if err != nil {
			return "", err
		}
		gcm, err := cipher.NewGCM(aesBlock)
		if err != nil {
			return "", err
		}
		nonce := make([]byte, gcm.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return "", err
		}
		ct := gcm.Seal(nil, nonce, []byte(plaintext), nil)
		recipients = append(recipients, dmRecipientCipher{
			PK: pkB64,
			N:  base64.StdEncoding.EncodeToString(nonce),
			CT: base64.StdEncoding.EncodeToString(ct),
		})
	}
	if len(recipients) == 0 {
		return "", fmt.Errorf("no recipient keys")
	}
	env := DMEnvelope{
		V:   dmEnvelopeVersionV2,
		Alg: dmEnvelopeAlgV2,
		SPK: base64.StdEncoding.EncodeToString(senderPriv.PublicKey().Bytes()),
		R:   recipients,
	}
	b, err := json.Marshal(env)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func DecryptDM(recipientPriv *ecdh.PrivateKey, body string) (string, error) {
	if recipientPriv == nil {
		return "", fmt.Errorf("missing recipient e2ee key")
	}
	var env DMEnvelope
	if err := json.Unmarshal([]byte(strings.TrimSpace(body)), &env); err != nil {
		return "", fmt.Errorf("not encrypted")
	}
	senderPubRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(env.SPK))
	if err != nil {
		return "", fmt.Errorf("invalid sender e2ee key")
	}
	senderPub, err := ecdh.X25519().NewPublicKey(senderPubRaw)
	if err != nil {
		return "", fmt.Errorf("invalid sender e2ee key")
	}
	shared, err := recipientPriv.ECDH(senderPub)
	if err != nil {
		return "", fmt.Errorf("ecdh failed")
	}
	key := deriveDMKey(shared, senderPubRaw, recipientPriv.PublicKey().Bytes())
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return "", err
	}
	switch {
	case env.V == dmEnvelopeVersionV2 && env.Alg == dmEnvelopeAlgV2:
		selfPK := base64.StdEncoding.EncodeToString(recipientPriv.PublicKey().Bytes())
		for _, r := range env.R {
			if strings.TrimSpace(r.PK) != selfPK {
				continue
			}
			nonce, err := base64.StdEncoding.DecodeString(strings.TrimSpace(r.N))
			if err != nil {
				return "", fmt.Errorf("invalid e2ee nonce")
			}
			ct, err := base64.StdEncoding.DecodeString(strings.TrimSpace(r.CT))
			if err != nil {
				return "", fmt.Errorf("invalid e2ee ciphertext")
			}
			pt, err := gcm.Open(nil, nonce, ct, nil)
			if err != nil {
				return "", fmt.Errorf("decrypt failed")
			}
			return string(pt), nil
		}
		return "", fmt.Errorf("no ciphertext for recipient key")
	case env.V == dmEnvelopeVersionV1 && env.Alg == dmEnvelopeAlgV1:
		nonce, err := base64.StdEncoding.DecodeString(strings.TrimSpace(env.N))
		if err != nil {
			return "", fmt.Errorf("invalid e2ee nonce")
		}
		ct, err := base64.StdEncoding.DecodeString(strings.TrimSpace(env.CT))
		if err != nil {
			return "", fmt.Errorf("invalid e2ee ciphertext")
		}
		pt, err := gcm.Open(nil, nonce, ct, nil)
		if err != nil {
			return "", fmt.Errorf("decrypt failed")
		}
		return string(pt), nil
	default:
		return "", fmt.Errorf("unsupported e2ee envelope")
	}
}

func deriveDMKey(shared []byte, senderPub []byte, recipientPub []byte) []byte {
	h := sha256.New()
	h.Write([]byte("goaccord-dm-e2ee-v1"))
	h.Write(shared)
	h.Write(senderPub)
	h.Write(recipientPub)
	sum := h.Sum(nil)
	key := make([]byte, 32)
	copy(key, sum)
	return key
}
