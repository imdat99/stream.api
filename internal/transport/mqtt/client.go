package mqtt

import (
	"context"
	"fmt"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

type Client interface {
	Publish(ctx context.Context, topic string, payload []byte) error
	Subscribe(topic string, handler MessageHandler) error
	Disconnect()
}

type MessageHandler func(topic string, payload []byte)

type client struct {
	cli mqtt.Client
}

func NewClient(broker string, clientID string) (Client, error) {
	opts := mqtt.NewClientOptions().
		AddBroker(broker).
		SetClientID(clientID).
		SetAutoReconnect(true).
		SetConnectRetry(true).
		SetConnectRetryInterval(3 * time.Second)

	opts.OnConnect = func(c mqtt.Client) {
		fmt.Println("MQTT connected")
	}

	opts.OnConnectionLost = func(c mqtt.Client, err error) {
		fmt.Println("MQTT connection lost:", err)
	}

	c := mqtt.NewClient(opts)

	token := c.Connect()
	if ok := token.WaitTimeout(5 * time.Second); !ok {
		return nil, fmt.Errorf("mqtt connect timeout")
	}
	if err := token.Error(); err != nil {
		return nil, err
	}

	return &client{cli: c}, nil
}

func (c *client) Publish(ctx context.Context, topic string, payload []byte) error {
	token := c.cli.Publish(topic, 1, false, payload)

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-waitToken(token):
		return token.Error()
	}
}

func waitToken(t mqtt.Token) <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		t.Wait()
		close(ch)
	}()
	return ch
}

func (c *client) Subscribe(topic string, handler MessageHandler) error {
	token := c.cli.Subscribe(topic, 1, func(client mqtt.Client, msg mqtt.Message) {
		handler(msg.Topic(), msg.Payload())
	})

	if token.Wait() && token.Error() != nil {
		return token.Error()
	}

	return nil
}

func (c *client) Disconnect() {
	c.cli.Disconnect(250)
}
