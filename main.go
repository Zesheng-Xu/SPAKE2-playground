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
	err := s.Init("Bob")
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		// Start the server
		log.Println("Starting the server on port 8080")
		log.Fatal(http.ListenAndServe(":8080", nil))
	}()

	// Create a SPAKE2HelloRequest
	req := spake2.SPAKE2HelloRequest{
		Identity: "Alice",
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

	// Decode the response body into the struct
	var helloResp spake2.SPAKE2HelloResponse
	err = json.NewDecoder(resp.Body).Decode(&helloResp)
	if err != nil {
		log.Fatal(err)
	}

	// Compute the client's public key
	client := spake2.Participant{}
	sharedParam := &spake2.SetUpParams{
		Prime: big.NewInt(pp),
		Pw:    pw,
		Suite: suite.P256,
	}
	client.Role = suite.Client
	client.Identity = "Alice"
	client.SetUp(sharedParam)
	client.OpponentIdentity = helloResp.Identity
	PointClient, err := client.ComputepPoint()
	if err != nil {
		log.Fatal(err)
	}

	// Create a SPAKE2PublickeyRequest
	pubKeyReq := spake2.SPAKE2PublickeyRequest{
		PubliCKey: PointClient,
	}

	// Encode the request into JSON
	reqBody, err = json.Marshal(pubKeyReq)
	if err != nil {
		log.Fatal(err)
	}

	// Send the public key to the server
	resp, err = http.Post("http://localhost:8080/clientPublicKey", "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	// Decode the response body into the struct
	var pubKeyResp spake2.SPAKE2PublicKeyResponse
	err = json.NewDecoder(resp.Body).Decode(&pubKeyResp)
	if err != nil {
		log.Fatal(err)
	}

	// Compute the shared key
	client.ComputepGroupElement(pubKeyResp.PublicKey)
	client.ComputeTranscript()
	client.DeriveKeys()

	// Create a SPAKE2MACRequest
	macReq := spake2.SPAKE2MACRequest{
		MACMessage: client.ProduceMacMessage(),
	}

	// Encode the request into JSON
	reqBody, err = json.Marshal(macReq)
	if err != nil {
		log.Fatal(err)
	}

	// Send the MAC to the server
	resp, err = http.Post("http://localhost:8080/clientMAC", "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	// Decode the response body into the struct
	var macResp spake2.SPAKE2MACResponse
	err = json.NewDecoder(resp.Body).Decode(&macResp)
	if err != nil {
		log.Fatal(err)
	}
	println("Server confirmed Client Mac")

	// Confirm the server's MAC
	confirm, err := client.ConfirmMAC(macResp.MACMessage)
	if err != nil || !confirm {
		log.Fatal("Error while confirming server MAC message")
	}
	println("Client confirmed Server Mac")

	// Now you can encrypt and decrypt messages using the derived keys
	message, _ := client.Encrypt([]byte("Hello World"))
	println("Client send encrypted text:" + string(message))

	message, _ = client.Decrypt(message)
	println("Server decrypted text:" + string(message))
}
