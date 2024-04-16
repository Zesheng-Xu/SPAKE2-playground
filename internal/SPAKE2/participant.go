package spake2

import (
	"SPAKE2-playground/internal/suite"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"strconv"
)

type Participant struct {
	Suite            *suite.Suite
	BigPrime         *big.Int
	X                *big.Int // random factor chosen between [0, p)
	H                *big.Int
	W                *big.Int
	M                *suite.Point
	WM               *suite.Point
	Pa               *suite.Point
	Pb               *suite.Point
	K                string
	Role             suite.Role
	Identity         string
	OpponentIdentity string
}

type SetUpParams struct {
	Role  suite.Role
	Pw    string
	M     *suite.Point
	Prime *big.Int
	Suite suite.SuiteOptions
}

// SetUp function sets the shared elements of the SPAKE
func (user *Participant) SetUp(param *SetUpParams) {

	user.Suite = suite.SelectECCSuite(param.Suite)
	user.Role = param.Role
	user.BigPrime = param.Prime
	user.H = new(big.Int).Div(user.Suite.Curve.Params().N, param.Prime)
	user.W = ComputeW(param.Pw, param.Prime)
	user.M = param.M

}

// ComputeW computes W that will be shared between server and client derived from password
func ComputeW(pw string, p *big.Int) *big.Int {
	hash := sha256.Sum256([]byte(pw))
	w := new(big.Int).SetBytes(hash[:])
	w.Mod(w, p)

	return w
}

// ComputepPoint generate special message transmitted to other party for key derivation
func (user *Participant) ComputepPoint() (p *suite.Point, err error) {
	x, err := rand.Int(rand.Reader, user.BigPrime)
	if err != nil {
		return &suite.Point{}, err
	}

	user.X = x
	pointX := user.Suite.BaseMultiply(x)
	pointWM := user.Suite.Multiply(user.M, user.W)

	user.WM = pointWM

	pointP := user.Suite.Add(pointX, pointWM)

	user.Pa = pointP

	return user.Pa, nil
}

// ComputepGroupElement finds K, the shared value across A and B
func (user *Participant) ComputepGroupElement(b *suite.Point) (k string) {
	ob := user.Suite.Subtract(b, user.WM)
	hx := new(big.Int).Mul(user.H, user.X)

	pointK := user.Suite.Multiply(ob, hx)

	user.Pb = b

	user.K = pointK.String()

	return user.K
}

func (user *Participant) ComputeTranscript() (tt string) {
	// TT = len(A)  || A
	// || len(B)  || B
	// || len(pA) || pA
	// || len(pB) || pB
	// || len(K)  || K
	// || len(w)  || w

	a, b := "", ""
	pA, pB := suite.Point{}, suite.Point{}

	switch user.Role {
	case suite.Server:
		a = user.Identity
		b = user.OpponentIdentity
		pA = *user.Pa
		pB = *user.Pb
	case suite.Client:
		a = user.OpponentIdentity
		b = user.Identity
		pA = *user.Pb
		pB = *user.Pa
	default:
		return ""
	}

	tt = strconv.Itoa(len(a)) + a +
		strconv.Itoa(len(b)) + b +
		strconv.Itoa(len(pA.String())) + pA.String() +
		strconv.Itoa(len(pB.String())) + pB.String() +
		strconv.Itoa(len(user.K)) + user.K +
		strconv.Itoa(len(user.W.String())) + user.W.String()

	return tt

}
