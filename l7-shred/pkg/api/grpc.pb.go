package api

import (
	"context"
	"net"

	"google.golang.org/grpc"
)

type ControlServer struct {
	grpc.UnimplementedControlServer
	port string
}

type Config struct {
	ListenPort int32
	SecretKey  []byte
	Mode       string
}

type Status struct {
	Connected bool
	BytesIn   uint64
	BytesOut  uint64
	Latency   int32
	SessionID uint64
}

type ControlServerInterface interface {
	GetConfig(ctx context.Context, req *Empty) (*Config, error)
	GetStatus(ctx context.Context, req *Empty) (*Status, error)
	UpdateConfig(ctx context.Context, req *Config) (*Status, error)
}

type Empty struct{}

func NewControlServer(port string) *ControlServer {
	return &ControlServer{port: port}
}

func (s *ControlServer) Start() error {
	lis, err := net.Listen("tcp", ":"+s.port)
	if err != nil {
		return err
	}

	grpcServer := grpc.NewServer()
	RegisterControlServer(grpcServer, s)

	return grpcServer.Serve(lis)
}

func (s *ControlServer) GetConfig(ctx context.Context, req *Empty) (*Config, error) {
	return &Config{
		ListenPort: 443,
		Mode:       "dual",
	}, nil
}

func (s *ControlServer) GetStatus(ctx context.Context, req *Empty) (*Status, error) {
	return &Status{
		Connected: true,
		BytesIn:   0,
		BytesOut:  0,
		Latency:   5,
		SessionID: 0,
	}, nil
}

func (s *ControlServer) UpdateConfig(ctx context.Context, req *Config) (*Status, error) {
	return &Status{Connected: true}, nil
}
