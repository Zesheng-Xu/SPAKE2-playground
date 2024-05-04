package server

import (
	"encoding/json"
	"fmt"
	"net/http"

	spake2 "github.com/Zesheng-Xu/SPAKE2-playground/internal/SPAKE2"
	"github.com/Zesheng-Xu/SPAKE2-playground/internal/suite"
)

type Server struct {
	clientMapping map[string]string
	spake         spake2.Participant
	httpClient    http.Client
}

var (
	clientPasswordMap = map[string]string{"Alice": "PythonISWAYBETTER"}
)

// TODO: create handler functions that will automatically proceed the SPAKE2 process

// Init function populates a new server instance
func (s Server) Init(identity string) (err error) {
	s.spake.Role = suite.Server
	s.spake.Identity = identity
	s.clientMapping, err = s.getClienMapping()
	if err != nil {
		return err
	}

	// Add the endpoints
	s.addFeatures()

	return nil
}

// HandleHello handles hello from client for SPAKE2
func (s Server) HandleHello(w http.ResponseWriter, r *http.Request) {
	// Decode the request body into the struct
	var req spake2.SPAKE2HelloRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	fmt.Println("Received a SPAKE2 HELLO from:", req.Identity)

	pw := s.clientMapping[req.Identity]
	if pw == "" {
		http.Error(w, "UnRecognized Client Identity", http.StatusBadRequest)
		return
	}

	setUpParam := &spake2.SetUpParams{
		Pw:               pw,
		OpponentIdentity: req.Identity,
		Prime:            req.Prime,
		Suite:            req.Suite,
	}

	s.spake.SetUp(setUpParam)

	// Create a response struct
	res := spake2.SPAKE2HelloResponse{
		Identity: s.spake.Identity,
		Suite:    string(s.spake.Suite.Name),
		Prime:    req.Prime,
	}

	// Encode the response into JSON and send it
	err = json.NewEncoder(w).Encode(res)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// HandleClientPublicKey handles public key presented by client
func (s Server) HandleClientPublicKey(w http.ResponseWriter, r *http.Request) {

	// Decode the request body into the struct
	var req spake2.SPAKE2PublickeyRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	fmt.Printf("Received a PA from %s: %s", s.spake.OpponentIdentity, req.PubliCKey.String())

	point, err := s.spake.ComputepPoint()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.spake.ComputepGroupElement(req.PubliCKey)
	s.spake.ComputeTranscript()
	s.spake.DeriveKeys()

	// Create a response struct
	res := spake2.SPAKE2PublicKeyResponse{PublicKey: point}

	// Encode the response into JSON and send it
	err = json.NewEncoder(w).Encode(res)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// HandleClientPublicKey handles public key presented by client
func (s Server) HandleClientMAC(w http.ResponseWriter, r *http.Request) {

	// Decode the request body into the struct
	var req spake2.SPAKE2MACRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	fmt.Printf("Received a MAC from %s: %s", s.spake.OpponentIdentity, string(req.MACMessage[:]))

	confirm, err := s.spake.ConfirmMAC(req.MACMessage)
	if err != nil || !confirm {
		http.Error(w, "while confirming client MAC message", http.StatusBadRequest)
		return
	}

	// Create a response struct
	res := spake2.SPAKE2MACResponse{MACMessage: s.spake.ProduceMacMessage()}

	// Encode the response into JSON and send it
	err = json.NewEncoder(w).Encode(res)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (s *Server) addFeatures() {
	http.HandleFunc("/hello", s.HandleHello)
	http.HandleFunc("/clientPublicKey", s.HandleClientPublicKey)
	http.HandleFunc("/clientMAC", s.HandleClientMAC)
}

//TODO: after mac-ing, decrypt and enceypt evey message from and to client

// getClienMapping returns clients mapped to their password
func (s Server) getClienMapping() (map[string]string, error) {
	return clientPasswordMap, nil
}
