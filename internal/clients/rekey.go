package clients

import (
	"time"

	//lint:ignore ST1001 reason: it's safer to use . import here to avoid name conflicts
	. "github.com/sem-hub/snake-net/internal/protocol/header"
)

type RekeyClient struct {
	client     *Client
	rekeyTimer *time.Timer
	rekeying   bool
	rekeyLock  chan struct{}
}

const (
	rekeyInterval = 1 * time.Minute
)

func NewRekeyForClient(client *Client, needTimer bool) *RekeyClient {
	rekey := &RekeyClient{
		client:    client,
		rekeying:  false,
		rekeyLock: make(chan struct{}, 1),
	}

	if needTimer {
		rekey.rekeyTimer = time.AfterFunc(rekeyInterval, func() { rekey.initiateRekey() })
	}
	return rekey
}

func (r *RekeyClient) initiateRekey() {
	// Check if already renegetiation in process
	select {
	case r.rekeyLock <- struct{}{}:
		// Got a lock. Continue.
	default:
		r.client.logger.Debug("Rekey already in progress, skipping", "address", r.client.address)
		r.resetRekeyTimer()
		return
	}

	defer func() { <-r.rekeyLock }()

	r.client.logger.Info("Initiating key renegotiation", "address", r.client.address)
	r.rekeying = true

	err := r.client.Write(nil, RenegReq|WithPadding)
	if err != nil {
		r.client.logger.Error("Failed to send rekey request", "address", r.client.address, "error", err)
		r.rekeying = false
		r.resetRekeyTimer()
		return
	}

	r.client.logger.Debug("Rekey request sent", "address", r.client.address)
}

func (r *RekeyClient) handleRenegReq() error {
	r.client.logger.Info("Received rekey request, performing ECDH", "address", r.client.address)

	err := r.client.Write(nil, RenegAck|WithPadding)
	if err != nil {
		r.client.logger.Error("Failed to send rekey acknowledgment", "address", r.client.address, "error", err)
		return err
	}

	err = r.client.ECDH()
	if err != nil {
		r.client.logger.Error("ECDH failed during rekey", "address", r.client.address, "error", err)
		return err
	}

	r.client.logger.Info("Rekey completed successfully", "address", r.client.address)
	return nil
}

func (r *RekeyClient) handleRenegAck() error {
	r.client.logger.Info("Received rekey acknowledgment", "address", r.client.address)

	err := r.client.ECDH()
	if err != nil {
		r.client.logger.Error("ECDH failed after receiving rekey acknowledgment", "address", r.client.address, "error", err)
		return err
	}

	r.client.logger.Info("Rekey completed successfully (initiator)", "address", r.client.address)
	r.rekeying = false
	r.resetRekeyTimer()
	return nil
}

func (r *RekeyClient) resetRekeyTimer() {
	if r.rekeyTimer != nil {
		r.rekeyTimer.Stop()
	}
	r.rekeyTimer = time.AfterFunc(rekeyInterval, func() { r.initiateRekey() })
	r.client.logger.Debug("Rekey timer reset", "address", r.client.address, "interval", rekeyInterval)
}

func (r *RekeyClient) Stop() {
	if r.rekeyTimer != nil {
		r.rekeyTimer.Stop()
	}
}
