package grpc

import (
	"sync"
	"time"

	"stream.api/internal/dto"
)

type AgentInfo struct {
	ID            string
	Name          string
	Platform      string
	Backend       string
	Version       string
	Capacity      int32
	CPU           float64
	RAM           float64
	LastHeartbeat time.Time
	ConnectedAt   time.Time
	CommandCh     chan string
}

type AgentManager struct {
	mu     sync.RWMutex
	agents map[string]*AgentInfo
}

func NewAgentManager() *AgentManager {
	return &AgentManager{agents: make(map[string]*AgentInfo)}
}

func (am *AgentManager) Register(id string, name, platform, backend, version string, capacity int32) {
	am.mu.Lock()
	defer am.mu.Unlock()
	now := time.Now()
	if existing, ok := am.agents[id]; ok {
		existing.Name = name
		existing.Platform = platform
		existing.Backend = backend
		existing.Version = version
		existing.Capacity = capacity
		existing.LastHeartbeat = now
		return
	}
	am.agents[id] = &AgentInfo{ID: id, Name: name, Platform: platform, Backend: backend, Version: version, Capacity: capacity, LastHeartbeat: now, ConnectedAt: now, CommandCh: make(chan string, 10)}
}

func (am *AgentManager) GetCommandChannel(id string) (chan string, bool) {
	am.mu.RLock()
	defer am.mu.RUnlock()
	agent, ok := am.agents[id]
	if !ok {
		return nil, false
	}
	return agent.CommandCh, true
}

func (am *AgentManager) SendCommand(id string, cmd string) bool {
	am.mu.RLock()
	defer am.mu.RUnlock()
	agent, ok := am.agents[id]
	if !ok {
		return false
	}
	select {
	case agent.CommandCh <- cmd:
		return true
	default:
		return false
	}
}

func (am *AgentManager) UpdateHeartbeat(id string) {
	am.mu.Lock()
	defer am.mu.Unlock()
	if agent, ok := am.agents[id]; ok {
		agent.LastHeartbeat = time.Now()
	}
}

func (am *AgentManager) UpdateResources(id string, cpu, ram float64) {
	am.mu.Lock()
	defer am.mu.Unlock()
	if agent, ok := am.agents[id]; ok {
		agent.CPU = cpu
		agent.RAM = ram
		agent.LastHeartbeat = time.Now()
	}
}

func (am *AgentManager) Unregister(id string) {
	am.mu.Lock()
	defer am.mu.Unlock()
	delete(am.agents, id)
}

func (am *AgentManager) ListAll() []*dto.Agent {
	am.mu.RLock()
	defer am.mu.RUnlock()
	now := time.Now()
	all := make([]*dto.Agent, 0, len(am.agents))
	for _, info := range am.agents {
		status := dto.AgentStatusOnline
		if now.Sub(info.LastHeartbeat) >= 60*time.Second {
			status = dto.AgentStatusOffline
		}
		all = append(all, &dto.Agent{ID: info.ID, Name: info.Name, Platform: info.Platform, Backend: info.Backend, Version: info.Version, Capacity: info.Capacity, Status: status, CPU: info.CPU, RAM: info.RAM, LastHeartbeat: info.LastHeartbeat, CreatedAt: info.ConnectedAt, UpdatedAt: info.LastHeartbeat})
	}
	return all
}
