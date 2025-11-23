package clients

import (
	"time"

	//lint:ignore ST1001 reason: it's safer to use . import here to avoid name conflicts
	. "github.com/sem-hub/snake-net/internal/interfaces"
)

type PingerClient struct {
	client           *Client
	lastPongTime     time.Time
	pingTimer        *time.Timer
	pongTimeoutTimer *time.Timer
	unansweredPings  int
}

const (
	pingInterval       = 5 * time.Second
	maxUnansweredPings = 3
	pingTimeout        = 1 * time.Second
)

func NewPingerForClient(client *Client) *PingerClient {
	pinger := &PingerClient{
		client:          client,
		lastPongTime:    time.Now(),
		unansweredPings: 0,
	}
	pinger.pingTimer = time.AfterFunc(pingInterval, func() { pinger.sendPing() })
	return pinger
}

func (p *PingerClient) ResetPingTimer() {
	p.unansweredPings = 0
	p.lastPongTime = time.Now()
	p.pingTimer.Reset(pingInterval)
}

func (p *PingerClient) StopPongTimeoutTimer() {
	if p.pongTimeoutTimer != nil {
		p.pongTimeoutTimer.Stop()
	}
}

func (p *PingerClient) sendPing() {
	// Set timeout timer
	p.pongTimeoutTimer = time.AfterFunc(pingTimeout, func() { p.PongTimeout() })
	p.unansweredPings++
	p.client.logger.Debug("Sending ping to client", "address", p.client.address.String())
	err := p.client.Write(nil, Ping|WithPadding)
	if err != nil {
		p.client.logger.Error("Failed to send ping to client", "address", p.client.address.String(), "error", err)
		return
	}
	// Schedule next ping
	p.pingTimer.Reset(pingInterval)
}

func (p *PingerClient) PongTimeout() {
	p.client.logger.Warn("Pong timeout, no pong received from client", "address", p.client.address.String())
	// If client just connected (no packets got from server yet), close after first timeout
	if p.client.GetClientState() == Connected || p.unansweredPings >= maxUnansweredPings {
		p.client.logger.Warn("Max unanswered pings reached, closing connection", "address", p.client.address.String())
		// Close the client connection and remove it
		RemoveClient(p.client.address)
	}
}
