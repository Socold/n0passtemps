package subject

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// decodePepper reads the pepper from its textual form.
//
// An encoding may be named with a prefix, "hex:", "base64:" or "raw:", and
// naming it is the recommended form. Without a prefix only the two unambiguous
// cases are accepted: hexadecimal, and base64 that decodes to at least
// MinPepperBytes.
//
// Everything else is refused rather than guessed at. An earlier version fell
// back to using the text itself as the key whenever decoding produced too few
// bytes. That silently accepted the base64 of a 24-byte secret as a 32
// character "passphrase": it worked, with a key carrying far less entropy than
// its length suggested, which is precisely the outcome a decoder for key
// material exists to prevent. A passphrase is still possible, but the operator
// has to say so with "raw:", and a guess is never made on their behalf.
func decodePepper(raw string) ([]byte, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, ErrPepperMissing
	}

	switch {
	case strings.HasPrefix(s, "hex:"):
		b, err := hex.DecodeString(strings.TrimPrefix(s, "hex:"))
		if err != nil {
			return nil, fmt.Errorf("subject: pepper is marked hex but does not decode: %w", err)
		}
		return b, nil

	case strings.HasPrefix(s, "base64:"):
		b, ok := decodeAnyBase64(strings.TrimPrefix(s, "base64:"))
		if !ok {
			return nil, fmt.Errorf("subject: pepper is marked base64 but does not decode")
		}
		return b, nil

	case strings.HasPrefix(s, "raw:"):
		return []byte(strings.TrimPrefix(s, "raw:")), nil
	}

	// Hex before base64: a hex string is also valid base64, and reading it as
	// base64 would yield a different, shorter key than the operator generated.
	if len(s)%2 == 0 && isHex(s) {
		return hex.DecodeString(s)
	}

	if b, ok := decodeAnyBase64(s); ok && len(b) >= MinPepperBytes {
		return b, nil
	}

	return nil, fmt.Errorf("%w: the value is not hexadecimal and is not base64 of at "+
		"least %d bytes. Generate one with \"n0passtemps-wizard pepper\", or prefix "+
		"the value with hex:, base64: or raw: to say what it is", ErrPepperShort, MinPepperBytes)
}

// decodeAnyBase64 accepts the four common base64 alphabets and paddings.
func decodeAnyBase64(s string) ([]byte, bool) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, true
		}
	}
	return nil, false
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}
