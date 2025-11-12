package clients

import "time"

type PingerClient struct {
	client          *Client
	lastPongTime    time.Time
	pingTimer       *time.Timer
	unansweredPings int
}

const pingInterval = 10 * time.Second
const maxUnansweredPings = 3

func NewPingerForClient(client *Client) *PingerClient {
	pinger := &PingerClient{
		client:          client,
		lastPongTime:    time.Now(),
		unansweredPings: 0,
	}
	pinger.pingTimer = time.AfterFunc(pingInterval, func() { pinger.sendPing() })
	return pinger
}

func (p *PingerClient) ResetTimer() {
	p.unansweredPings = 0
	p.lastPongTime = time.Now()
	p.pingTimer.Reset(pingInterval)
}

func (p *PingerClient) sendPing() {
	if p.unansweredPings >= maxUnansweredPings {
		p.client.logger.Warn("No pong received from client, closing connection", "address", p.client.address.String())
		// Close the client connection and remove it
		RemoveClient(p.client.address)
		return
	}
	p.unansweredPings++
	p.client.logger.Debug("Sending ping to client", "address", p.client.address.String())
	buf := MakePadding()
	err := p.client.Write(&buf, Ping)
	if err != nil {
		p.client.logger.Error("Failed to send ping to client", "address", p.client.address.String(), "error", err)
		return
	}
	// Schedule next ping
	p.pingTimer.Reset(pingInterval)
}
