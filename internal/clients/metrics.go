package clients

import (
	"net/netip"
	"sort"
)

type ClientMetricsSnapshot struct {
	Address   string `json:"address"`
	InPkt     int    `json:"in_pkt"`
	OutPkt    int    `json:"out_pkt"`
	InBytes   int    `json:"in_bytes"`
	OutBytes  int    `json:"out_bytes"`
	OOOPkts   int    `json:"ooo_pkts"`
	ErrorPkts int    `json:"error_pkts"`
}

type ClientConnectionSnapshot struct {
	Address            string   `json:"address"`
	IP                 string   `json:"ip"`
	TunAddrs           []string `json:"tun_addrs"`
	Transport          string   `json:"transport,omitempty"`
	CipherAlgorithm    string   `json:"cipher_algorithm,omitempty"`
	SignatureAlgorithm string   `json:"signature_algorithm,omitempty"`
}

func (c *Client) metricsSnapshot() ClientMetricsSnapshot {
	c.metricsLock.RLock()
	defer c.metricsLock.RUnlock()

	return ClientMetricsSnapshot{
		Address:   c.address.String(),
		InPkt:     c.Metrics.inPkt,
		OutPkt:    c.Metrics.outPkt,
		InBytes:   c.Metrics.inBytes,
		OutBytes:  c.Metrics.outBytes,
		OOOPkts:   c.Metrics.oooPkts,
		ErrorPkts: c.Metrics.errorPkts,
	}
}

func GetClientMetricsByIP(ip netip.Addr) (ClientMetricsSnapshot, bool) {
	clientsLock.RLock()
	defer clientsLock.RUnlock()

	ip = ip.Unmap()
	for _, client := range clients {
		if client == nil {
			continue
		}
		if client.address.Addr().Unmap() == ip {
			return client.metricsSnapshot(), true
		}
	}

	return ClientMetricsSnapshot{}, false
}

func GetAllClientsMetrics() []ClientMetricsSnapshot {
	clientsLock.RLock()
	defer clientsLock.RUnlock()

	metrics := make([]ClientMetricsSnapshot, 0, len(clients))
	for _, client := range clients {
		if client == nil {
			continue
		}
		metrics = append(metrics, client.metricsSnapshot())
	}

	sort.Slice(metrics, func(i, j int) bool {
		return metrics[i].Address < metrics[j].Address
	})

	return metrics
}

func GetConnectedClientsInfo() []ClientConnectionSnapshot {
	clientsLock.RLock()
	defer clientsLock.RUnlock()

	clientsInfo := make([]ClientConnectionSnapshot, 0, len(clients))
	for _, client := range clients {
		if client == nil {
			continue
		}

		info := ClientConnectionSnapshot{
			Address:  client.address.String(),
			IP:       client.address.Addr().String(),
			TunAddrs: make([]string, 0, len(client.tunAddrs)),
		}

		for _, cidr := range client.tunAddrs {
			info.TunAddrs = append(info.TunAddrs, cidr.String())
		}

		if client.t != nil {
			info.Transport = client.t.GetName()
		}

		if client.secrets != nil {
			if client.secrets.Engine != nil {
				info.CipherAlgorithm = client.secrets.Engine.GetName()
			}
			if client.secrets.SignatureEngine != nil {
				info.SignatureAlgorithm = client.secrets.SignatureEngine.GetName()
			}
		}

		clientsInfo = append(clientsInfo, info)
	}

	sort.Slice(clientsInfo, func(i, j int) bool {
		return clientsInfo[i].Address < clientsInfo[j].Address
	})

	return clientsInfo
}
