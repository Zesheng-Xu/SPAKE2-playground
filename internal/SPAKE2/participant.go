package spake2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"strconv"

	"github.com/Zesheng-Xu/SPAKE2-playground/internal/suite"
)

type Participant struct {
	Suite                   *suite.Suite
	BigPrime                *big.Int
	X                       *big.Int // random factor chosen between [0, p)
	H                       *big.Int
	W                       *big.Int
	M                       *suite.Point
	N                       *suite.Point
	WM                      *suite.Point
	WN                      *suite.Point
	Pa                      *suite.Point
	Pb                      *suite.Point
	K                       string
	TT                      string
	Role                    suite.Role
	Identity                string
	OpponentIdentity        string
	SessionConfirmationKey  []byte
	ExpectedConfirmationKey []byte
	SessionPrivateKey       []byte
}

type SetUpParams struct {
	Pw               string
	OpponentIdentity string
	Prime            *big.Int
	Suite            suite.SuiteOptions
}

const (
	mString = "M SPAKE2 seed OID %s"
	nString = "N SPAKE2 seed OID %s"
)

// SetUp function sets the shared elements of the SPAKE
func (user *Participant) SetUp(param *SetUpParams) {

	user.Suite = suite.SelectECCSuite(param.Suite)
	user.BigPrime = param.Prime
	user.OpponentIdentity = param.OpponentIdentity

	user.H = new(big.Int).Div(user.Suite.Curve.Params().N, param.Prime)
	user.M, user.N = user.CalculatePublicPoints()

	user.W = user.ComputeW(param.Pw)
}

// CalculatePublicPoints calculates M and N used by server and client respectivly
func (user *Participant) CalculatePublicPoints() (m, n *suite.Point) {
	m = user.Suite.HashToCurve(fmt.Sprintf(mString, user.Suite.GetName()))
	n = user.Suite.HashToCurve(fmt.Sprintf(nString, user.Suite.GetName()))

	switch user.Role {
	case suite.Server:
		return m, n
	default:
		return n, m
	}

}

// ComputeW computes W that will be shared between server and client derived from password
func (user *Participant) ComputeW(pw string) *big.Int {
	hash := user.Suite.Hash(pw)
	w := new(big.Int).SetBytes(hash[:])
	w.Mod(w, user.Suite.Curve.Params().P)

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

	pointWN := user.Suite.Multiply(user.N, user.W)
	user.WN = pointWN

	pointP := user.Suite.Add(pointX, pointWM)
	user.Pa = pointP

	return user.Pa, nil
}

// ComputepGroupElement finds K, the shared value across A and B
func (user *Participant) ComputepGroupElement(b *suite.Point) (k string) {
	ob := user.Suite.Subtract(b, user.WN)
	hx := new(big.Int).Mul(user.H, user.X)

	pointK := user.Suite.Multiply(ob, hx)

	user.Pb = b

	user.K = pointK.String()

	return user.K
}

// ComputeTranscript creates a TT transcript for this SPAKE2 exchange
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

	user.TT = strconv.Itoa(len(a)) + a +
		strconv.Itoa(len(b)) + b +
		strconv.Itoa(len(pA.String())) + pA.String() +
		strconv.Itoa(len(pB.String())) + pB.String() +
		strconv.Itoa(len(user.K)) + user.K +
		strconv.Itoa(len(user.W.String())) + string(user.W.Bytes())

	return user.TT
}

// DeriveKeys generate 3 byte arrays:
// Ke: session key that be used to encrypt and decrypt the messages
// kca: this participant's half of the confirmation key
// kcb: other participant's half of the confirmation key
func (user *Participant) DeriveKeys() (ke, kca, kcb []byte) {

	ke, kca, kcb = user.Suite.KDF(user.TT)

	user.SessionPrivateKey = ke

	switch user.Role {
	case suite.Client:
		// switch order on client since Client is b
		user.SessionConfirmationKey = kcb
		user.ExpectedConfirmationKey = kca
	default:
		user.SessionConfirmationKey = kca
		user.ExpectedConfirmationKey = kcb
	}

	return ke, kca, kcb
}

// Encrypt function creates an encrypted text based on drived session key and provided plain text
func (user *Participant) Encrypt(plainText []byte) ([]byte, error) {
	block, err := aes.NewCipher(user.SessionPrivateKey)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plainText))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plainText)

	return ciphertext, nil
}

// Decrypt function decrypts message received based on derived key
func (user *Participant) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(user.SessionPrivateKey)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}

// ConfirmMAC takes received bytes and check if it matches to this participant's half of confirmation key
func (user *Participant) ConfirmMAC(receivedMAC []byte) (bool, error) {

	receivedKey, err := user.Decrypt(receivedMAC)
	if err != nil {
		return false, err
	}

	return user.Suite.MAC([]byte(receivedKey), user.ExpectedConfirmationKey, []byte(user.TT)), nil

}

// ProduceMacMessage creates Mac message based on RFC-9382 defiend format
func (user *Participant) ProduceMacMessage() []byte {

	msg, err := user.Encrypt(user.SessionConfirmationKey)
	if err != nil {
		return nil
	}

	return msg
}

func Encode(b []byte) []byte {

	out := []byte{}

	base64.StdEncoding.Encode(out, b)

	return out
}

func Decode(s []byte) ([]byte, error) {

	out := []byte{}

	_, err := base64.StdEncoding.Decode(out, s)

	return out, err
}
