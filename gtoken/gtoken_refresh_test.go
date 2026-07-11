package gtoken

import (
	"context"
	"crypto/subtle"
	"testing"
	"time"
)

func TestRefreshCredentialRoundTrip(t *testing.T) {
	raw, digest, err := newRefreshCredential("family-1")
	if err != nil {
		t.Fatal(err)
	}

	familyID, secret, err := parseRefreshCredential(raw)
	if err != nil {
		t.Fatal(err)
	}
	if familyID != "family-1" {
		t.Fatalf("family id = %q, want family-1", familyID)
	}
	if len(secret) != refreshSecretBytes {
		t.Fatalf("secret bytes = %d, want %d", len(secret), refreshSecretBytes)
	}

	got := digestRefreshSecret(secret)
	if subtle.ConstantTimeCompare(got[:], digest[:]) != 1 {
		t.Fatal("refresh digest mismatch")
	}
}

func TestNewTokenUsesInjectedClock(t *testing.T) {
	ctx := context.Background()
	start := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	m := &GToken{
		ExpireIn: 24 * time.Hour,
		Clock:    func() time.Time { return start },
	}
	m.Init(ctx)

	_, info, err := m.NewToken(ctx, "user-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := start.Add(24 * time.Hour); !info.ExpireAt.Time.Equal(want) {
		t.Fatalf("expire at = %s, want %s", info.ExpireAt, want)
	}
	if want := start.Add(12 * time.Hour); !info.RefreshAt.Time.Equal(want) {
		t.Fatalf("refresh at = %s, want %s", info.RefreshAt, want)
	}
}

func TestInitSetsRefreshDefaults(t *testing.T) {
	m := &GToken{}
	m.Init(context.Background())
	if m.RefreshExpireIn != DefaultRefreshExpireIn {
		t.Fatalf("refresh expire in = %s, want %s", m.RefreshExpireIn, DefaultRefreshExpireIn)
	}
	if m.RefreshLimit != DefaultRefreshLimit {
		t.Fatalf("refresh limit = %d, want %d", m.RefreshLimit, DefaultRefreshLimit)
	}
}

func TestNowUsesInjectedClock(t *testing.T) {
	want := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	m := &GToken{Clock: func() time.Time { return want }}
	if got := m.now(); !got.Equal(want) {
		t.Fatalf("now = %s, want %s", got, want)
	}
}

func TestParseRefreshCredentialRejectsMalformed(t *testing.T) {
	tests := []string{
		"",
		"missing-separator",
		".c2VjcmV0",
		"family.not-base64!",
		"family.c2hvcnQ",
		"family.a.b",
	}

	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			if _, _, err := parseRefreshCredential(raw); err == nil {
				t.Fatalf("parseRefreshCredential(%q) unexpectedly succeeded", raw)
			}
		})
	}
}
