package engine

import (
	"github.com/l7-shred/core/internal/transport"
)

type Server struct {
	config  *transport.Config
	inbound *transport.Inbound
}

func NewServer(config *transport.Config) *Server {
	return &Server{
		config: config,
	}
}

func (s *Server) Start() error {
	inbound, err := transport.NewInbound(s.config)
	if err != nil {
		return err
	}

	s.inbound = inbound

	return s.inbound.Start()
}

func (s *Server) Stop() error {
	if s.inbound != nil {
		return s.inbound.Stop()
	}
	return nil
}
