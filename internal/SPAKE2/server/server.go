package server

import (
	"net/http"

	spake2 "github.com/Zesheng-Xu/SPAKE2-playground/internal/SPAKE2"
)

type Server struct {
	spake      spake2.Participant
	httpClient http.Client
}

// TODO: create handler functions that will automatically proceed the SPAKE2 process

func (s Server) Init() {

}
