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

const L = 256 // len(Kc) defiend by RFC 9382

func NewP256Suite() *Suite {
	s := &P256Suite{}
	s.Suite.Name = "P256"
	s.Suite.Curve = elliptic.P256()
	s.Suite.Add = s.Add
	s.Suite.Multiply = s.Multiply
	s.Suite.Hash = s.Hash
	s.Suite.KDF = s.KDF
	s.Suite.MAC = s.MAC
	s.Suite.L = L
	return &s.Suite

}

// Init initializes the P256Suite.
func (s *P256Suite) Init() *P256Suite {
	s.Suite.Name = "P256"
	s.Suite.Curve = elliptic.P256()
	return s
}

// Name returns the name of the Suite.
func (s *P256Suite) Name() string {
	return s.Suite.Name
}

// Curve returns the elliptic curve of the Suite.
func (s *P256Suite) Curve() elliptic.Curve {
	return s.Suite.Curve
}

// Add adds two points on the elliptic curve.
func (s *P256Suite) Add(point1, point2 *Point) *Point {
	x, y := s.Suite.Curve.Add(point1.X, point1.Y, point2.X, point2.Y)
	return &Point{X: x, Y: y}
}

// Multiply multiplies a point by a scalar on the elliptic curve.
func (s *P256Suite) Multiply(point1 *Point, N *big.Int) *Point {
	x, y := s.Suite.Curve.ScalarMult(point1.X, point1.Y, N.Bytes())
	return &Point{X: x, Y: y}
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

// MAC uses RFC 9382 define MAC function to validate received confirmation key
func (s *P256Suite) MAC(kca []byte, kcb []byte, tt []byte) bool {

	mac1 := hmac.New(sha256.New, kca)
	mac1.Write(tt) // Include the protocol transcript or other data here
	macA := mac1.Sum(nil)

	// Party B
	mac2 := hmac.New(sha256.New, kcb)
	mac2.Write(tt) // Must be the same data as used by A
	macb := mac2.Sum(nil)
	return subtle.ConstantTimeCompare(macA, macb) == 1
}
