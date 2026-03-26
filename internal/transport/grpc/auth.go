package grpc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	proto "stream.api/internal/api/proto/agent/v1"
)

func generateToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func generateAgentID() string {
	return strconv.FormatInt(time.Now().UnixNano(), 10)
}

func (s *Server) getAgentIDFromContext(ctx context.Context) (string, string, bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", "", false
	}
	tokens := md.Get("token")
	if len(tokens) == 0 {
		return "", "", false
	}
	token := tokens[0]
	if id, ok := s.sessions.Load(token); ok {
		return id.(string), token, true
	}
	return "", "", false
}

func (s *Server) Auth(ctx context.Context, req *proto.AuthRequest) (*proto.AuthResponse, error) {
	if s.agentSecret != "" && req.AgentToken != s.agentSecret {
		return nil, status.Error(codes.Unauthenticated, "invalid agent secret")
	}
	agentID := req.AgentId
	if len(agentID) > 6 && agentID[:6] == "agent-" {
		agentID = agentID[6:]
	}
	if agentID == "" {
		agentID = generateAgentID()
	}
	accessToken := generateToken()
	s.sessions.Store(accessToken, agentID)
	return &proto.AuthResponse{Status: "ok", AgentId: agentID, AccessToken: accessToken}, nil
}
