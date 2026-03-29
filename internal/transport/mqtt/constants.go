package mqtt

import "time"

const (
	defaultMQTTBrokerURL = "tcp://broker.mqtt-dashboard.com:1883"
	defaultMQTTPrefix    = "picpic"
	defaultPublishWait   = 5 * time.Second
)

type mqttEvent struct {
	Type    string `json:"type"`
	Payload any    `json:"payload"`
}
