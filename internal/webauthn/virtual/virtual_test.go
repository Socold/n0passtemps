package virtual

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
)

// Two packages verify real ceremonies against this authenticator, so a fault in
// it would not fail their tests: it would make them pass for the wrong reason,
// by producing something the relying party happens to accept. The tests below
// check the authenticator against the specification rather than against a
// relying party, so the two are never the same witness.

const (
	testOrigin = "https://auth.example.com"
	testRPID   = "auth.example.com"
)

// creationOptionsJSON is the shape a relying party sends for a registration.
func creationOptionsJSON(challenge string) json.RawMessage {
	return json.RawMessage(`{"publicKey":{
		"challenge":"` + challenge + `",
		"rp":{"id":"` + testRPID + `","name":"Example"},
		"user":{"id":"dXNlci0x","name":"user-1","displayName":"User One"}
	}}`)
}

// requestOptionsJSON is the shape a relying party sends for an assertion.
func requestOptionsJSON(challenge string, allow []byte) json.RawMessage {
	pk := map[string]any{"challenge": challenge, "rpId": testRPID}
	if allow != nil {
		pk["allowCredentials"] = []any{
			map[string]any{"type": "public-key", "id": base64.RawURLEncoding.EncodeToString(allow)},
		}
	}
	raw, err := json.Marshal(map[string]any{"publicKey": pk})
	if err != nil {
		panic(err)
	}
	return raw
}

func newTestAuthenticator() *Authenticator {
	return New(testOrigin, [16]byte{9, 8, 7, 6})
}

// TestClientDataCarriesTheOriginAndChallengeVerbatim is the field a relying
// party checks first, and the one a mistake here would make permanently wrong.
func TestClientDataCarriesTheOriginAndChallengeVerbatim(t *testing.T) {
	a := newTestAuthenticator()
	const challenge = "Y2hhbGxlbmdlLTE"

	raw, err := a.Create(creationOptionsJSON(challenge))
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	var cred struct {
		Response struct {
			ClientDataJSON string `json:"clientDataJSON"`
		} `json:"response"`
	}
	if err = json.Unmarshal(raw, &cred); err != nil {
		t.Fatalf("parse credential: %v", err)
	}
	data, err := base64.RawURLEncoding.DecodeString(cred.Response.ClientDataJSON)
	if err != nil {
		t.Fatalf("decode clientDataJSON: %v", err)
	}

	var client map[string]any
	if err = json.Unmarshal(data, &client); err != nil {
		t.Fatalf("parse clientDataJSON: %v", err)
	}
	// The member names are the specification's, lower case. A struct tag that
	// capitalised one of these would still round-trip through this
	// authenticator and be refused by every real relying party.
	if client["origin"] != testOrigin {
		t.Errorf("origin = %v, want %q", client["origin"], testOrigin)
	}
	if client["challenge"] != challenge {
		t.Errorf("challenge = %v, want %q", client["challenge"], challenge)
	}
	if client["type"] != "webauthn.create" {
		t.Errorf("type = %v, want webauthn.create", client["type"])
	}
}

// TestAnAssertionNamesTheCredentialItWasSignedWith closes the loop between the
// two ceremonies.
func TestAnAssertionNamesTheCredentialItWasSignedWith(t *testing.T) {
	a := newTestAuthenticator()

	if _, err := a.Create(creationOptionsJSON("Y3JlYXRl")); err != nil {
		t.Fatalf("create: %v", err)
	}
	if a.Last == nil || len(a.Last.ID) == 0 {
		t.Fatal("creation left no credential behind")
	}

	raw, err := a.Get(requestOptionsJSON("YXNzZXJ0", a.Last.ID))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	var got struct {
		RawID    string `json:"rawId"`
		Response struct {
			Signature string `json:"signature"`
		} `json:"response"`
	}
	if err = json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("parse assertion: %v", err)
	}
	if want := base64.RawURLEncoding.EncodeToString(a.Last.ID); got.RawID != want {
		t.Errorf("rawId = %q, want %q", got.RawID, want)
	}
	if got.Response.Signature == "" {
		t.Error("the assertion carries no signature")
	}
}

// TestTheCounterAdvancesAndCanBeHeld is what the clone tests elsewhere rest on.
//
// If ForceCounter did not actually hold the counter, the test that checks a
// stalled counter raises an alert would be checking nothing, and it would still
// pass, because the service raises no alert when the counter advances.
func TestTheCounterAdvancesAndCanBeHeld(t *testing.T) {
	a := newTestAuthenticator()
	if _, err := a.Create(creationOptionsJSON("Y3JlYXRl")); err != nil {
		t.Fatalf("create: %v", err)
	}

	counters := func() uint32 {
		t.Helper()
		raw, err := a.Get(requestOptionsJSON("YXNzZXJ0", a.Last.ID))
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		var got struct {
			Response struct {
				AuthenticatorData string `json:"authenticatorData"`
			} `json:"response"`
		}
		if err = json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("parse: %v", err)
		}
		data, err := base64.RawURLEncoding.DecodeString(got.Response.AuthenticatorData)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		// Section 6.1: rpIdHash(32) || flags(1) || signCount(4, big endian).
		if len(data) < 37 {
			t.Fatalf("authenticator data is %d bytes, too short to carry a counter", len(data))
		}
		return uint32(data[33])<<24 | uint32(data[34])<<16 | uint32(data[35])<<8 | uint32(data[36])
	}

	first, second := counters(), counters()
	if second <= first {
		t.Errorf("counter went %d then %d; it must advance on every assertion", first, second)
	}

	a.ForceCounter(second)
	if held := counters(); held != second {
		t.Errorf("ForceCounter(%d) produced %d; the clone tests rest on this holding", second, held)
	}
}

// TestAnAllowListThatNamesNothingHeldIsRefused is the case a lost authenticator
// produces, and the error the tests elsewhere match on.
func TestAnAllowListThatNamesNothingHeldIsRefused(t *testing.T) {
	a := newTestAuthenticator()
	if _, err := a.Create(creationOptionsJSON("Y3JlYXRl")); err != nil {
		t.Fatalf("create: %v", err)
	}

	_, err := a.Get(requestOptionsJSON("YXNzZXJ0", []byte("a-credential-this-device-never-held")))
	if !errors.Is(err, ErrNoMatchingCredential) {
		t.Errorf("err = %v, want ErrNoMatchingCredential", err)
	}
}

// TestCreatingTwiceUnderOneRelyingPartyKeepsBothCredentials, because a subject
// is allowed more than one authenticator and the tests enrol several.
func TestCreatingTwiceUnderOneRelyingPartyKeepsBothCredentials(t *testing.T) {
	a := newTestAuthenticator()
	for _, challenge := range []string{"Zmlyc3Q", "c2Vjb25k"} {
		if _, err := a.Create(creationOptionsJSON(challenge)); err != nil {
			t.Fatalf("create %s: %v", challenge, err)
		}
	}
	if len(a.Credentials) != 2 {
		t.Errorf("the authenticator holds %d credentials, want 2", len(a.Credentials))
	}
}

// TestMalformedOptionsAreRefusedRatherThanSigned keeps a broken test from
// looking like a working one.
func TestMalformedOptionsAreRefusedRatherThanSigned(t *testing.T) {
	a := newTestAuthenticator()

	for name, options := range map[string]json.RawMessage{
		"no challenge": json.RawMessage(`{"publicKey":{"rp":{"id":"` + testRPID +
			`"},"user":{"id":"dXNlcg"}}}`),
		"no relying party": json.RawMessage(`{"publicKey":{"challenge":"Yw","user":{"id":"dXNlcg"}}}`),
		"no user":          json.RawMessage(`{"publicKey":{"challenge":"Yw","rp":{"id":"` + testRPID + `"}}}`),
		"not an object":    json.RawMessage(`"options"`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := a.Create(options); err == nil {
				t.Error("malformed creation options were signed")
			}
		})
	}

	if _, err := a.Get(json.RawMessage(`{"publicKey":{"rpId":"` + testRPID + `"}}`)); err == nil {
		t.Error("request options with no challenge were signed")
	}
}
