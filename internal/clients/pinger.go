package clients

import "time"

type PingerClient struct {
	client       *Client
	lastPongTime time.Time
	pingTimer    *time.Timer
}

const pingInterval = 10 * time.Second

func NewPingerForClient(client *Client) *PingerClient {
	pinger := &PingerClient{
		client:       client,
		lastPongTime: time.Now(),
	}
	pinger.pingTimer = time.AfterFunc(pingInterval, func() { pinger.sendPing() })
	return pinger
}

func (p *PingerClient) ResetTimer() {
	p.pingTimer.Reset(pingInterval)
}

func (p *PingerClient) sendPing() {
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
