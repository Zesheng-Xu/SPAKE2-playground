// Package main to launch service.
package main

import (
	spake2 "SPAKE2-playground/internal/SPAKE2"
	"SPAKE2-playground/internal/suite"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
)

var (
	// password shared by the client and server
	pw = "PythonISWAYBETTER"

	// a prime that they chose to use
	pp = int64(1231231234542132117)
)

//TODO: implement/upgrade to SPAKE2+ once this is done

// Main function.
func main() {

	test := big.NewInt(50000)
	by := test.Bytes()
	println(by)

	server := spake2.Participant{}
	client := spake2.Participant{}

	// TODO: find out how and actual implement the Hash_to_curve function
	// faking M and N
	// rather then generating from hash_to_curve, using a random point on curve instead
	m, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		println(err.Error())
	}

	sharedParam := &spake2.SetUpParams{
		Prime: big.NewInt(pp),
		Pw:    pw,
		M:     &suite.Point{X: m.PublicKey.X, Y: m.PublicKey.Y},
		Suite: suite.P256,
	}

	err = server.SetUp(sharedParam)
	if err != nil {
		println(err.Error())
	}
	err = client.SetUp(sharedParam)
	if err != nil {
		println(err.Error())
	}

	server.Role = suite.Server // This Determines the A and B when generating Transcript
	client.Role = suite.Client

	server.Identity = "Alice"
	client.Identity = "Bob"

	server.OpponentIdentity = client.Identity
	client.OpponentIdentity = server.Identity

	PointServer, err := server.ComputepPoint()
	if err != nil {
		println(err.Error())
	}

	PointClient, err := client.ComputepPoint()
	if err != nil {
		println(err.Error())
	}

	println("Selected ECC: " + server.Suite.Name)

	println(fmt.Sprintf("Server p - big prime: %s, \n Client p - big prime: %s,", server.BigPrime, client.BigPrime))
	println(fmt.Sprintf("Server w derived from password: %s, \n Client w derived from password: %s,", server.W, client.W))
	println(fmt.Sprintf("Server H: %s, \n Client H: %s,", server.H, client.H))
	println(fmt.Sprintf("Server x - random factor [0, p): %s, \n Client x - random factor [0, p): %s,", server.X, client.X))
	println(fmt.Sprintf("Server pA: %s, \n Client pB: %s,", server.Pa, client.Pa))
	sk := server.ComputepGroupElement(PointClient)

	ck := client.ComputepGroupElement(PointServer)

	println(fmt.Sprintf("Server calculated k to derive session key: %s, \n Client calculated k to derive session key: %s,", sk, ck))

	stt := server.ComputeTranscript()

	ctt := client.ComputeTranscript()

	println(fmt.Sprintf("Server TT to input KDF: %s, \n Client TT to input KDF: %s,", stt, ctt))

	server.DeriveKeys()

	client.DeriveKeys()

	sMac, _ := server.ConfirmMAC(client.ProduceMacMessage())
	cMac, _ := client.ConfirmMAC(server.ProduceMacMessage())

	println("Server confirm Client MAC:", sMac)
	println("Client confirm Server MAC:", cMac)

	message, _ := client.Encrypt([]byte("Hello World"))
	println("Client send encrypted text:" + string(message))

	message, _ = server.Decrypt(message)
	println("Server decrypted text:" + string(message))
}
