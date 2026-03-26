package grpc

import "sync"

func (s *Server) trackJobAssignment(agentID, jobID string) {
	jobSetInterface, _ := s.agentJobs.LoadOrStore(agentID, &sync.Map{})
	if jobSet, ok := jobSetInterface.(*sync.Map); ok {
		jobSet.Store(jobID, true)
	}
}

func (s *Server) untrackJobAssignment(agentID, jobID string) {
	if jobSetInterface, ok := s.agentJobs.Load(agentID); ok {
		if jobSet, ok := jobSetInterface.(*sync.Map); ok {
			jobSet.Delete(jobID)
		}
	}
}

func (s *Server) isJobAssigned(agentID, jobID string) bool {
	if jobSetInterface, ok := s.agentJobs.Load(agentID); ok {
		if jobSet, ok := jobSetInterface.(*sync.Map); ok {
			_, found := jobSet.Load(jobID)
			return found
		}
	}
	return false
}

func (s *Server) getAgentJobs(agentID string) []string {
	jobs := []string{}
	if jobSetInterface, ok := s.agentJobs.Load(agentID); ok {
		if jobSet, ok := jobSetInterface.(*sync.Map); ok {
			jobSet.Range(func(key, _ any) bool {
				if jobID, ok := key.(string); ok {
					jobs = append(jobs, jobID)
				}
				return true
			})
		}
	}
	return jobs
}
