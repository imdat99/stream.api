package mqtt

import (
	"encoding/json"
	"fmt"
	"time"

	pahomqtt "github.com/eclipse/paho.mqtt.golang"
	"stream.api/pkg/logger"
)

func connectPahoClient(broker, clientID string) (pahomqtt.Client, error) {
	opts := pahomqtt.NewClientOptions().
		AddBroker(broker).
		SetClientID(clientID).
		SetAutoReconnect(true).
		SetConnectRetry(true).
		SetKeepAlive(60 * time.Second).
		SetPingTimeout(10 * time.Second).
		SetConnectRetryInterval(3 * time.Second)

	client := pahomqtt.NewClient(opts)
	token := client.Connect()
	if ok := token.WaitTimeout(defaultPublishWait); !ok {
		return nil, fmt.Errorf("mqtt connect timeout")
	}
	if err := token.Error(); err != nil {
		return nil, err
	}

	return client, nil
}

func publishMQTTEvent(client pahomqtt.Client, appLogger logger.Logger, prefix string, event mqttEvent) {
	if client == nil {
		return
	}

	if err := publishMQTTJSON(client, fmt.Sprintf("%s/events", prefix), event); err != nil {
		appLogger.Error("Failed to publish MQTT event", "error", err, "type", event.Type)
	}
}

func publishMQTTJSON(client pahomqtt.Client, topic string, payload any) error {
	if client == nil {
		return nil
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return publishPahoMessage(client, topic, encoded)
}

func publishPahoMessage(client pahomqtt.Client, topic string, payload []byte) error {
	if client == nil {
		return nil
	}
	token := client.Publish(topic, 0, false, payload)
	if ok := token.WaitTimeout(defaultPublishWait); !ok {
		return fmt.Errorf("mqtt publish timeout")
	}
	return token.Error()
}
