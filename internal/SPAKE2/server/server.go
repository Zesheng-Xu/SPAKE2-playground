package server

import (
	spake2 "SPAKE2-playground/internal/SPAKE2"
	"net/http"
)

type Server struct {
	spake      spake2.Participant
	httpClient http.Client
}

// TODO: create handler functions that will automatically proceed the SPAKE2 process

func (s Server) Init() {

}
