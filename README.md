# snake-net
Snake net is a tunnel protocol.

This is my project to improve skills in networking, tunneling, cryptography, etc. in Go.

Features:
 * Both TOML config and command line seting up. (Command line overrides config).
 * Separate logging for every module
 * TUN interface
 * Own packet format (with very little overhead: only 9 bytes header)
 * Random padding for fixed-size packets
 * Transport agnostic. Supports:
   * TCP
   * UDP
   * TLS
   * DTLS
   * QUIC
 * Encrypt and verify packets for TCP and UDP
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
      * Aegis (очень быстрый)
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
 * For TLS protocols (TLS, DTLS and QUIC): dynamic certificate creating or load them from files
 * Dynamic address assigments (both IPv4&IPv6)
 * Works on Linux and Windows
 * SOCKS5 server on remote node (don't use it on local node. It's useless)
