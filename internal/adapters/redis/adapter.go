package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"stream.api/internal/database/model"
	"stream.api/internal/dto"
)

const (
	JobQueueKey      = "render:jobs:queue"
	LogChannel       = "render:jobs:logs"
	ResourceChannel  = "render:agents:resources"
	JobUpdateChannel = "render:jobs:updates"
)

type RedisAdapter struct{ client *goredis.Client }

func NewAdapter(addr, password string, db int) (*RedisAdapter, error) {
	client := goredis.NewClient(&goredis.Options{Addr: addr, Password: password, DB: db})
	if err := client.Ping(context.Background()).Err(); err != nil {
		return nil, err
	}
	return &RedisAdapter{client: client}, nil
}

func (r *RedisAdapter) Client() *goredis.Client { return r.client }

func (r *RedisAdapter) Enqueue(ctx context.Context, job *model.Job) error {
	data, err := json.Marshal(job)
	if err != nil {
		return err
	}
	timestamp := time.Now().UnixNano()
	score := float64(-(int64(*job.Priority) * 1000000000) - timestamp)
	return r.client.ZAdd(ctx, JobQueueKey, goredis.Z{Score: score, Member: data}).Err()
}

func (r *RedisAdapter) Dequeue(ctx context.Context) (*model.Job, error) {
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		res, err := r.client.ZPopMin(ctx, JobQueueKey, 1).Result()
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, err
		}
		if len(res) == 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Second):
				continue
			}
		}
		var raw []byte
		switch member := res[0].Member.(type) {
		case string:
			raw = []byte(member)
		case []byte:
			raw = member
		default:
			return nil, fmt.Errorf("unexpected redis queue payload type %T", member)
		}
		var job model.Job
		if err := json.Unmarshal(raw, &job); err != nil {
			return nil, err
		}
		return &job, nil
	}
}

func (r *RedisAdapter) Publish(ctx context.Context, jobID string, logLine string, progress float64) error {
	payload, err := json.Marshal(dto.LogEntry{JobID: jobID, Line: logLine, Progress: progress})
	if err != nil {
		return err
	}
	return r.client.Publish(ctx, LogChannel, payload).Err()
}

func (r *RedisAdapter) Subscribe(ctx context.Context, jobID string) (<-chan dto.LogEntry, error) {
	pubsub := r.client.Subscribe(ctx, LogChannel)
	ch := make(chan dto.LogEntry)
	go func() {
		defer close(ch)
		defer pubsub.Close()
		for msg := range pubsub.Channel() {
			var entry dto.LogEntry
			if err := json.Unmarshal([]byte(msg.Payload), &entry); err != nil {
				continue
			}
			if jobID == "" || entry.JobID == jobID {
				ch <- entry
			}
		}
	}()
	return ch, nil
}

func (r *RedisAdapter) PublishResource(ctx context.Context, agentID string, data []byte) error {
	var decoded struct {
		CPU float64 `json:"cpu"`
		RAM float64 `json:"ram"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	payload, err := json.Marshal(dto.SystemResource{AgentID: agentID, CPU: decoded.CPU, RAM: decoded.RAM})
	if err != nil {
		return err
	}
	return r.client.Publish(ctx, ResourceChannel, payload).Err()
}

func (r *RedisAdapter) SubscribeResources(ctx context.Context) (<-chan dto.SystemResource, error) {
	pubsub := r.client.Subscribe(ctx, ResourceChannel)
	ch := make(chan dto.SystemResource)
	go func() {
		defer close(ch)
		defer pubsub.Close()
		for msg := range pubsub.Channel() {
			var entry dto.SystemResource
			if err := json.Unmarshal([]byte(msg.Payload), &entry); err != nil {
				continue
			}
			ch <- entry
		}
	}()
	return ch, nil
}

func (r *RedisAdapter) PublishCancel(ctx context.Context, agentID string, jobID string) error {
	return r.client.Publish(ctx, fmt.Sprintf("render:agents:%s:cancel", agentID), jobID).Err()
}

func (r *RedisAdapter) SubscribeCancel(ctx context.Context, agentID string) (<-chan string, error) {
	pubsub := r.client.Subscribe(ctx, fmt.Sprintf("render:agents:%s:cancel", agentID))
	ch := make(chan string)
	go func() {
		defer close(ch)
		defer pubsub.Close()
		for msg := range pubsub.Channel() {
			ch <- msg.Payload
		}
	}()
	return ch, nil
}

func (r *RedisAdapter) PublishJobUpdate(ctx context.Context, jobID string, status string, videoID string) error {
	payload, err := json.Marshal(map[string]string{"job_id": jobID, "status": status, "video_id": videoID})
	if err != nil {
		return err
	}
	return r.client.Publish(ctx, JobUpdateChannel, payload).Err()
}

func (r *RedisAdapter) SubscribeJobUpdates(ctx context.Context) (<-chan string, error) {
	pubsub := r.client.Subscribe(ctx, JobUpdateChannel)
	ch := make(chan string)
	go func() {
		defer close(ch)
		defer pubsub.Close()
		for msg := range pubsub.Channel() {
			ch <- msg.Payload
		}
	}()
	return ch, nil
}
func (c *RedisAdapter) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	return c.client.Set(ctx, key, value, expiration).Err()
}

func (c *RedisAdapter) Get(ctx context.Context, key string) (string, error) {
	return c.client.Get(ctx, key).Result()
}

func (c *RedisAdapter) Del(ctx context.Context, key string) error {
	return c.client.Del(ctx, key).Err()
}

func (c *RedisAdapter) Close() error {
	return c.client.Close()
}
