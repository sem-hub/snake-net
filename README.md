# snake-net
Snake net is a tunnel protocol

Features:
 * Both TOML config and command line seting up. (Command line overrides config).
 * TUN interface
 * Own packet format
 * Random padding for fixed-size packets
 * Transport agnostic. Supports:
   * TCP
   * UDP
   * TLS
   * DTLS
   * QUIC
 * Encrypt and verify packets for TCP and UDP
 * For TLS protocols: dynamic certificate creating or load them from files
 * Dynamic address assigments (both IPv4&IPv6) [plans]
 * Works on Linux and Windows
