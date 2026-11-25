# snake-net
Snake net is a tunnel protocol.

This is my project to improve skills in networking, tunneling, cryptography, etc. in Go.

Features:
 * Both TOML config and command line seting up. (Command line overrides config).
 * Separate logging for every module.
 * TUN interface.
 * Own packet format (with very little overhead: only 9 bytes header).
 * Random padding for fixed-size packets.
 * Transport agnostic. Supports:
   * TCP
   * UDP
   * TLS
   * DTLS
   * QUIC
   * KCP
 * Encrypt and verify packets for TCP and UDP.
   * Supported block, stram and AEAD ciphers:
     * Block ciphers (universal with modes):
       * AES
       * Speck
       * Threefish
       * RC6
     * Stream ciphers:
       * Chacha20
       * Salsa20
       * Rabbit
       * HC-256
    * AEAD ciphers:
      * Chacha20-Poly1305
      * XSalsa20-Poly1305 (Nonce size=24 in comparing with Salsa20-Poly1305 where Nonce=8)
      * Aegis (very fast)
      * Grain
    * Cipher modes (makes block cipher in stream or AEAD):
      * CBC (block)
      * CTR (stream)
      * GCM (AEAD)
      * CCM (AEAD)
      * OCB (AEAD)
      * EAX (AEAD)
 * AEAD ciphers don't need a packet verification, but block and stream do.
    * Supported signature algorythms:
      * ED25519 asymetric keys algorythm
      * HMAC-SHA256 - SHA256 based MAC
      * HMAC-Blake2b
      * Poly1305
 * For TLS protocols (TLS, DTLS and QUIC): dynamic certificate creating or load them from files.
 * For TLS protocol use uTLS ClientHello comuflage.
 * Dynamic address assigments (both IPv4&IPv6).
 * Works on Linux and Windows.
 * SOCKS5 server on remote node (don't use it on local node. It's useless).
 * Auto protocol and port number discovery with ICMP request. You need only server address (and secret) for connect.
 * REST API for client metrics.

## Config file

```toml
[main]
server = false # true for server mode, false for client mode
secret = "not_simply_password"      # secret key. Mandatory for both client and server modes.
id = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" # for client mode. Will be generated temporary if not specified
protocol = "tcp"    # or "udp", "quic", "tls", "dtls", "kcp"
verbose = "Info"      # default log level for all modules, can be overridden by module-specific settings below
remote_addr = "hostname.or.ip"  # mandatory for client mode
remote_port = 12345 # 0 means to ask server for the port
prefer_ipv6 = true  # prefer IPv6 addresses when resolving server name
prefer_ipv4 = true  # prefer IPv4 addresses when resolving server name
discovery = true        # server discovery protocol and port number
#local_addr = "local.ip.address" # listen on the IP (for server mode)
#local_port = 12345 # listen on the port (for server mode) 0 means to listen on a random port
attempts = 1                    # Attempt count for first connection, 0 means infinity
retry_delay = 5               # seconds
reconnect = false              # reconnect automatically in client mode if server drop connection
api_port = 0                   # API server port, 0 means to disable API server
[crypt]
engine = "aes-cbc"          # optional. will be get from server if not specified
sign_engine = "ed25519"     # optional. will be get from server if not specified
[tls]
cert_file = ""              # will generated if not specified
priv_key_file = ""
fingerprint = "chrome" # uTLS client fingerprint: chrome, firefox, ios, edge, safari, 360, qq, randomized
[tun]
tun_addr = ["10.0.0.10/24","fd11::10/64"] # mandatory for serever and optional for client. Will be get from server if not specified.
mtu = 1420
name = "snake"      # interface name. "tun" if not specified
[socks5]
enabled = false
port = 1080
username = ""
password = ""
[log]
file = ""      # log file path, empty means stdout
nocolor = false  # disable color output on stdout
main = "Error"
protocol = "Debug"
route = "Info"
crypt = "Info"
clients = "Info"
tun = "info"
transport = "info"
socks5 = "info"
icmp = "info"
firewall = "info"
```

## Command line arguments
All command line flags overrides config file.

### Long flags versions

```text
-4
      alias to prefer_ipv4
-6
      alias to prefer_ipv6
-api int
        Enable REST API on specified port.
-attempts int
        Number of connection attempts before giving up (0 means infinite). (default 1)
-cert string
        Path to TLS/DTLS certificate file (overrides config file).
-cipher string
        Cipher to use (overrides config file).
-config string
        Path to config file.
-debug
        Enable debug mode (alias to -log=main=Debug,network=Debug,tun=Debug,route=Debug,protocol=Debug,clients=Debug,crypt=Debug,transport=Debug).
-discovery
        Enable discovery mode.
-fingerprint string
        TLS fingerprint to use.
-id string
        Client ID.
-key string
        Secret key.
-local string
        Local address (overrides config file).
-log value
        Logging levels may be overridden by this.
-mtu int
        MTU size. (default 1500)
-name string
        Name of tun interface.
-prefer_ipv4
        Prefer IPv4 for remote address resolution.
-prefer_ipv6
        Prefer IPv6 for remote address resolution.
-privkey string
        Path to TLS/DTLS private key file (overrides config file).
-proto string
        Protocol to use (tcp or udp). Overrides config file setting.
-retry int
        Delay in seconds between connection attempts. (default 5)
-server
        Server mode (otherwise client mode).
-sign string
        Signature engine to use (overrides config file).
-socks5 int
        Enable SOCKS5 proxy on specified port.
-socks5pass string
        SOCKS5 proxy password.
-socks5user string
        SOCKS5 proxy username.
-tun value
        Comma separated IPv4 and IPv6 Addresses (CIDR) for Tun interface.
-verbose string
        Default logging level for all modules.
```

### Short aliases

```text
-A int
        alias to api
-C string
        alias to cert
-D value
        alias to log
-K string
        alias to privkey
-a int
        alias to attempts (default 1)
-c string
        alias to config
-d
      alias to debug
-e string
        alias to cipher
-f string
        alias to fingerprint
-g string
        alias to sign
-i string
        alias to id
-k string
        alias to key
-l string
        alias to local
-n string
        alias to name
-p string
        alias to proto
-r int
        alias to retry (default 5)
-s
      alias to server
-t value
        alias to tun
-u int
        alias to mtu (default 1500)
-v string
        alias to verbose
-x int
        alias to socks5
-y
      alias to discovery
```
