package suite

import (
	"crypto/elliptic"
	"math/big"
)

// P256Suite represents a Suite that uses the P-256 elliptic curve.
type P256Suite struct {
	Suite
}

func NewP256Suite() *Suite {
	s := &P256Suite{}
	s.Suite.Name = "P256"
	s.Suite.Curve = elliptic.P256()
	s.Suite.Add = s.Add
	s.Suite.Multiply = s.Multiply
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
