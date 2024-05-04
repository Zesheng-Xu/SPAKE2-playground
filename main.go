// Package main to launch service.
package main

import (
	"bytes"
	"encoding/json"
	"log"
	"math/big"
	"net/http"

	spake2 "github.com/Zesheng-Xu/SPAKE2-playground/internal/SPAKE2"
	"github.com/Zesheng-Xu/SPAKE2-playground/internal/SPAKE2/server"
	"github.com/Zesheng-Xu/SPAKE2-playground/internal/suite"
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

	// Initialize the server
	s := &server.Server{}
	err := s.Init("ServerIdentity")
	if err != nil {
		log.Fatal(err)
	}

	// Start the server
	log.Println("Starting the server on port 8080")
	log.Fatal(http.ListenAndServe(":8080", nil))

	// Create a SPAKE2HelloRequest
	req := spake2.SPAKE2HelloRequest{
		Identity: "Bob",
		Suite:    suite.P256,
		Prime:    big.NewInt(pp),
	}

	// Encode the request into JSON
	reqBody, err := json.Marshal(req)
	if err != nil {
		log.Fatal(err)
	}

	// Send the request to the server
	resp, err := http.Post("http://localhost:8080/hello", "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	// Print the response status
	log.Println("Response status:", resp.Status)

	//TODO remove these code - reference for now
	// server := spake2.Participant{}
	// client := spake2.Participant{}

	// sharedParam := &spake2.SetUpParams{
	// 	Prime: big.NewInt(pp),
	// 	Pw:    pw,
	// 	Suite: suite.P256,
	// }

	// server.Role = suite.Server // This Determines the A and B when generating Transcript
	// client.Role = suite.Client

	// server.Identity = "Alice"
	// client.Identity = "Bob"

	// server.SetUp(sharedParam)

	// client.SetUp(sharedParam)

	// server.OpponentIdentity = client.Identity
	// client.OpponentIdentity = server.Identity

	// PointServer, err := server.ComputepPoint()
	// if err != nil {
	// 	println(err.Error())
	// }

	// PointClient, err := client.ComputepPoint()
	// if err != nil {
	// 	println(err.Error())
	// }

	// println("Selected ECC: " + server.Suite.Name)

	// println(fmt.Sprintf("Server p - big prime: %s, \n Client p - big prime: %s,", server.BigPrime, client.BigPrime))
	// println(fmt.Sprintf("Server w derived from password: %s, \n Client w derived from password: %s,", server.W, client.W))
	// println(fmt.Sprintf("Server H: %s, \n Client H: %s,", server.H, client.H))
	// println(fmt.Sprintf("Server x - random factor [0, p): %s, \n Client x - random factor [0, p): %s,", server.X, client.X))
	// println(fmt.Sprintf("Server pA: %s, \n Client pB: %s,", server.Pa, client.Pa))
	// sk := server.ComputepGroupElement(PointClient)

	// ck := client.ComputepGroupElement(PointServer)

	// println(fmt.Sprintf("Server calculated k to derive session key: %s, \n Client calculated k to derive session key: %s,", sk, ck))

	// stt := server.ComputeTranscript()

	// ctt := client.ComputeTranscript()

	// println(fmt.Sprintf("Server TT to input KDF: %s, \n Client TT to input KDF: %s,", stt, ctt))

	// server.DeriveKeys()

	// client.DeriveKeys()

	// sMac, _ := server.ConfirmMAC(client.ProduceMacMessage())
	// cMac, _ := client.ConfirmMAC(server.ProduceMacMessage())

	// println("Server confirm Client MAC:", sMac)
	// println("Client confirm Server MAC:", cMac)

	// message, _ := client.Encrypt([]byte("Hello World"))
	// println("Client send encrypted text:" + string(message))

	// message, _ = server.Decrypt(message)
	// println("Server decrypted text:" + string(message))
}
