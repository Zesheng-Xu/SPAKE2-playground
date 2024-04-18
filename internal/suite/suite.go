package suite

import (
	"crypto/elliptic"
	"math/big"
)

type Suite struct {
	Name  SuiteOptions
	Curve elliptic.Curve
	L     int      //key length
	A     *big.Int // const A
	Hash  func(str string) [32]byte
	KDF   func(tt string) ([]byte, []byte, []byte)
	MAC   func(kca []byte, kcb []byte, tt []byte) bool
}

// GetName Return name of the suite
func (s *Suite) GetName() SuiteOptions {
	return s.Name
}

// GetCurve return the curve of the suite
func (s *Suite) GetCurve() elliptic.Curve {
	return s.Curve
}

// Add adds two points on the elliptic curve.
func (s *Suite) Add(p1, p2 *Point) *Point {

	var slope, x3, y3 big.Int

	p := s.Curve.Params().P

	if p1.X.Cmp(p2.X) == 0 && p1.Y.Cmp(p2.Y) == 0 { // p1 is equal to p2
		// slope = (3 * x1^2 + a) / 2 * y1
		slope.Mul(p1.X, p1.X)                         // x1^2
		slope.Mul(&slope, big.NewInt(3))              // 3 * x1^2
		slope.Add(&slope, s.A)                        // 3 * x1^2 + a
		temp := new(big.Int).Mul(p1.Y, big.NewInt(2)) // 2 * y1
		temp.ModInverse(temp, p)                      // (2 * y1)^-1
		slope.Mul(&slope, temp)                       // (3 * x1^2 + a) / 2 * y1
		slope.Mod(&slope, p)                          // mod p
	} else {
		// slope = (y2 - y1) / (x2 - x1)
		slope.Sub(p2.Y, p1.Y)                // y2 - y1
		temp := new(big.Int).Sub(p2.X, p1.X) // x2 - x1
		temp.ModInverse(temp, p)             // (x2 - x1)^-1
		slope.Mul(&slope, temp)              // (y2 - y1) / (x2 - x1)
		slope.Mod(&slope, p)                 // mod p
	}

	// x3 = slope^2 - x1 - x2
	x3.Mul(&slope, &slope) // slope^2
	x3.Sub(&x3, p1.X)      // slope^2 - x1
	x3.Sub(&x3, p2.X)      // slope^2 - x1 - x2
	x3.Mod(&x3, p)         // mod p

	// y3 = slope * (x1 - x3) - y1
	y3.Sub(p1.X, &x3)   // x1 - x3
	y3.Mul(&slope, &y3) // slope * (x1 - x3)
	y3.Sub(&y3, p1.Y)   // slope * (x1 - x3) - y1
	y3.Mod(&y3, p)      // mod p

	return &Point{&x3, &y3}
}

// Multiply multiplies a point by a scalar on the elliptic curve.
func (s *Suite) Multiply(p1 *Point, n *big.Int) *Point {

	// just handle some basic cases
	if n.Cmp(big.NewInt(0)) == 0 {
		return &Point{}
	} else if n.Cmp(big.NewInt(1)) == 0 {
		return p1
	}

	// Doing double and add method
	// get big endian form of the n first
	// example: big.NewInt(50000).Bytes() = [ 195, 80 ] = [11000011. 01010000] = 1100001101010000
	bigEndianBytes := n.Bytes()

	binaryBits := []bool{}

	// convert big int to binary
	for _, b := range bigEndianBytes {
		binaryBits = append(binaryBits, uint8ToBinaryBits(b)...)
	}

	// remove leading zeros
	for index, b := range binaryBits {
		if b == true {
			binaryBits = binaryBits[index:]
			break
		}
	}

	// pop leading 1 if possible
	if len(binaryBits) > 1 {
		binaryBits = binaryBits[1:]
	}

	// starting 1 p
	p := p1
	// iterate through the binary bits
	for _, b := range binaryBits {

		// double p
		pp := s.Add(p, p)

		// add if the bit is 1
		if b {
			pp = s.Add(p, pp)
		}

		p = pp
	}

	compX, compY := s.Curve.ScalarMult(p1.X, p1.Y, n.Bytes())
	println(compX, compY)

	// Return the resulting point
	return p
}

// BaseMultiply returns n*G where G is the generator point of the curve
func (s *Suite) BaseMultiply(n *big.Int) (resultPoint *Point) {
	return s.Multiply(&Point{s.Curve.Params().Gx, s.Curve.Params().Gy}, n)
}

// Subtract return point result of point1 - point2 on the given curve
func (s *Suite) Subtract(point1, point2 *Point) (resultPoint *Point) {
	return s.Add(point1, point2.Negate(s.Curve.Params().P))
}

// IsOnCurve Checks if the provided point lies on the EC
func (s *Suite) IsOnCurve(p *Point) bool {
	// y ^ 2 mod p
	left := new(big.Int).Exp(p.Y, big.NewInt(2), s.Curve.Params().P)

	// x ^ 3
	right := new(big.Int).Exp(p.X, big.NewInt(3), s.Curve.Params().P)

	// - 3x
	right = right.Add(right, new(big.Int).Mul(p.X, s.A))

	// + b
	right = right.Add(right, s.Curve.Params().B)

	// mod q
	right = right.Mod(right, s.Curve.Params().P)

	return left.Cmp(right) == 0
}

func uint8ToBinaryBits(num uint8) []bool {
	bits := make([]bool, 8) // Initialize a slice to store the bits

	// Extract each bit
	for i := 0; i < 8; i++ {
		bits[7-i] = (num & (1 << uint(i))) != 0
	}

	return bits
}

type Point struct {
	X, Y *big.Int
}

// Negate returns the  negated of provided point
func (p *Point) Negate(P *big.Int) *Point {
	negatedY := new(big.Int).Neg(p.Y)
	negatedY.Mod(negatedY, P) // Take the result modulo P

	negatedPoint := Point{
		X: p.X,
		Y: negatedY,
	}

	return &negatedPoint
}

// Do you really need a comment for this ?
func (p *Point) String() string {
	return p.X.String() + "|" + p.Y.String()
}
