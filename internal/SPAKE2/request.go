package spake2

import (
	"math/big"

	"github.com/Zesheng-Xu/SPAKE2-playground/internal/suite"
)

type SPAKE2HelloRequest struct {
	Identity string
	Suite    suite.SuiteOptions
	Prime    *big.Int
}

type SPAKE2PublickeyRequest struct {
	PubliCKey *suite.Point
}

type SPAKE2MACRequest struct {
	MACMessage []byte
}
