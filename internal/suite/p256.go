package suite

import (
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"io"
	"math/big"

	"golang.org/x/crypto/hkdf"
)

// P256Suite represents a Suite that uses the P-256 elliptic curve.
type P256Suite struct {
	Suite
}

// Equation for P256
// y^2 = x^3 - 3x + 41058363725152142129326129780047268409114441015993725554835256314039467401291

const L = 256 // len(Kc) defiend by RFC 9382
var A = big.NewInt(-3)

// NewP256Suite creates a new suite object with function and parameters for NIST P256 curve
func NewP256Suite() *Suite {
	// IDK how to make this easier
	s := &P256Suite{}
	s.Suite.Name = P256
	s.Suite.Curve = elliptic.P256()
	s.Suite.Hash = s.Hash
	s.Suite.KDF = s.KDF
	s.Suite.MAC = s.MAC
	s.Suite.L = L
	s.Suite.A = A

	return &s.Suite
}

// Hash defines the hash function used for this suite, following RFC 9382
func (s *P256Suite) Hash(str string) [32]byte {
	hash := sha256.Sum256([]byte(str))
	return hash
}

// KDF defines the Key Deriving used for this suite, following RFC 9382
func (s *P256Suite) KDF(str string) ([]byte, []byte, []byte) {
	hashedTranscript := s.Hash(str)

	ke := hashedTranscript[0 : len(hashedTranscript)/2]
	ka := hashedTranscript[len(hashedTranscript)/2:]

	// Create a new HKDF extractor
	hkdf := hkdf.New(sha256.New, ka, nil, []byte("ConfirmationKeys"))

	// Extract and expand the key material
	kc := make([]byte, L)
	if _, err := io.ReadFull(hkdf, kc); err != nil {
		panic(err)
	}

	return ke, kc[0 : len(kc)/2], kc[len(kc)/2:]
}

// MAC uses RFC 9382 defined MAC function to validate received confirmation key
func (s *P256Suite) MAC(kca []byte, kcb []byte, tt []byte) bool {

	mac1 := hmac.New(sha256.New, kca)
	mac1.Write(tt) // Include the protocol transcript
	macA := mac1.Sum(nil)

	// Party B
	mac2 := hmac.New(sha256.New, kcb)
	mac2.Write(tt) // Must be the same data as used by A, but why? Ke is derived from TT, this is validating samething twice
	macb := mac2.Sum(nil)
	return subtle.ConstantTimeCompare(macA, macb) == 1
}
