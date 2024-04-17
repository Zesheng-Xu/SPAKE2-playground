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
	// IDK how to make this easier
	s := &P256Suite{}
	s.Suite.Name = "P256"
	s.Suite.Curve = elliptic.P256()
	s.Suite.Add = s.Add
	s.Suite.Multiply = s.Multiply
	s.Suite.Hash = s.Hash
	s.Suite.KDF = s.KDF
	s.Suite.MAC = s.MAC
	s.Suite.IsOnCurve = s.IsOnCurve
	s.Suite.L = L
	return &s.Suite

}

// Init initializes the P256Suite.
func (s *P256Suite) Init() *P256Suite {
	s.Suite.Name = "P256"
	s.Suite.Curve = elliptic.P256()
	return s
}

// IsOnCurve Checks if the provided point lies on the EC
func (s *P256Suite) IsOnCurve(p *Point) bool {

	// Equation for P256 is  y ^ 2 = x ^ 3 - 3x + b mod q

	// y ^ 2 mod p
	left := new(big.Int).Exp(p.Y, big.NewInt(2), s.Curve.Params().P)

	// x ^ 3
	right := new(big.Int).Exp(p.X, big.NewInt(3), s.Curve.Params().P)

	// - 3x
	right = right.Sub(right, new(big.Int).Mul(p.X, big.NewInt(3)))

	// + b
	right = right.Add(right, s.Curve.Params().B)

	// mod q
	right = right.Mod(right, s.Curve.Params().P)

	return left.Cmp(right) == 0
}

// Add adds two points on the elliptic curve.
func (s *P256Suite) Add(p1, p2 *Point) *Point {

	var slope, x3, y3 big.Int

	p := s.Curve.Params().P

	if p1.X.Cmp(p2.X) == 0 && p1.Y.Cmp(p2.Y) == 0 { // p1 is equal to p2
		// slope = (3 * x1^2 + a) / 2 * y1
		slope.Mul(p1.X, p1.X)                         // x1^2
		slope.Mul(&slope, big.NewInt(3))              // 3 * x1^2
		slope.Add(&slope, big.NewInt(-3))             // 3 * x1^2 + a
		temp := new(big.Int).Mul(p1.Y, big.NewInt(2)) // 2 * y1
		temp.ModInverse(temp, p)                      // (2 * y1)^-1
		slope.Mul(&slope, temp)                       // (3 * x1^2 + a) / 2 * y1
		slope.Mod(&slope, p)
	} else {
		// slope = (y2 - y1) / (x2 - x1)
		slope.Sub(p2.Y, p1.Y)                // y2 - y1
		temp := new(big.Int).Sub(p2.X, p1.X) // x2 - x1
		temp.ModInverse(temp, p)             // (x2 - x1)^-1
		slope.Mul(&slope, temp)              // (y2 - y1) / (x2 - x1)
		slope.Mod(&slope, p)
	}

	// x3 = slope^2 - x1 - x2
	x3.Mul(&slope, &slope) // slope^2
	x3.Sub(&x3, p1.X)      // slope^2 - x1
	x3.Sub(&x3, p2.X)      // slope^2 - x1 - x2
	x3.Mod(&x3, p)

	// y3 = slope * (x1 - x3) - y1
	y3.Sub(p1.X, &x3)   // x1 - x3
	y3.Mul(&slope, &y3) // slope * (x1 - x3)
	y3.Sub(&y3, p1.Y)   // slope * (x1 - x3) - y1
	y3.Mod(&y3, p)

	return &Point{&x3, &y3}
}

// Multiply multiplies a point by a scalar on the elliptic curve.
func (s *P256Suite) Multiply(p1 *Point, n *big.Int) *Point {

	// Initialize result as the "point at infinity"
	result := &Point{big.NewInt(0), big.NewInt(0)}

	// TODO: Implement the double and add algorithm and remove the deprecated function

	result.X, result.Y = s.Curve.ScalarMult(p1.X, p1.Y, n.Bytes())

	// Return the resulting point
	return result

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
