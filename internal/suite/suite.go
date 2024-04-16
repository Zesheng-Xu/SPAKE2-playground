package suite

import (
	"crypto/elliptic"
	"math/big"
)

type Suite struct {
	Name     string
	Curve    elliptic.Curve
	L        int //key length
	Add      func(point1, point2 *Point) (resultPoint *Point)
	Multiply func(point1 *Point, N *big.Int) (resultPoint *Point)
	Hash     func(str string) [32]byte
	KDF      func(tt string) ([]byte, []byte, []byte)
	MAC      func(kca []byte, kcb []byte, tt []byte) bool
}

func (s *Suite) GetName() string {
	return s.Name
}

func (s *Suite) GetCurve() elliptic.Curve {
	return s.Curve
}

func (s *Suite) BaseMultiply(n *big.Int) (resultPoint *Point) {
	return s.Multiply(&Point{s.Curve.Params().Gx, s.Curve.Params().Gy}, n)
}

func (s *Suite) Subtract(point1, point2 *Point) (resultPoint *Point) {
	return s.Add(point1, point2.Negate(s.Curve.Params().P))
}

type Point struct {
	X, Y *big.Int
}

func (p *Point) Negate(P *big.Int) *Point {
	negatedY := new(big.Int).Neg(p.Y)
	negatedY.Mod(negatedY, P) // Take the result modulo P

	negatedPoint := Point{
		X: p.X,
		Y: negatedY,
	}

	return &negatedPoint
}

func (p *Point) String() string {
	return p.X.String() + "|" + p.Y.String()
}
