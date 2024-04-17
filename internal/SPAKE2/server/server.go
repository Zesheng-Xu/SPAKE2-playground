package server

import (
	spake2 "SPAKE2-playground/internal/SPAKE2"
	"net/http"
)

type Server struct {
	spake      spake2.Participant
	httpClient http.Client
}

func (s Server) Init() {

}
