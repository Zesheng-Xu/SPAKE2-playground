package spake2

import (
	"math/big"

	"github.com/Zesheng-Xu/SPAKE2-playground/internal/suite"
)

type ErrorResponse struct {
	Message string
}

type SPAKE2HelloResponse struct {
	Identity string
	Suite    string
	Prime    *big.Int
}

type SPAKE2PublicKeyResponse struct {
	PublicKey *suite.Point
}

type SPAKE2MACResponse struct {
	MACMessage []byte
}
