# snake-net
Snake net is a tunnel protocol.

This is my project to improve skills in networking, tunneling, cryptography, etc. in Go.

Features:
 * Both TOML config and command line seting up. (Command line overrides config).
 * Separate logging for every module [in progress]
 * TUN interface
 * Own packet format (with very little overhead)
 * Random padding for fixed-size packets
 * Transport agnostic. Supports:
   * TCP
   * UDP
   * TLS
   * DTLS
   * QUIC
 * Encrypt and verify packets for TCP and UDP
   * Supported block, stram and AEAD ciphers:
     * block ciphers:
       * AES-CBC
       * Present (very light and fast)
       * IDEA
       * Twofish
       * Threefish
       * RC6
     * stream ciphers:
       * AES-CTR
       * Chacha20
       * Salsa20
    * AEAD ciphers:
      * AES-GCM
      * Chacha20-Poly1305
      * XSalsa20-Poly1305 (Nonce size=24 in comparing with Salsa20-Poly1305 where Nonce=8)
 * AEAD ciphers don't need a packet verification, but block and stream do.
    * Supported signature algorythms:
      * ED25519 asymetric keys algorythm
      * HMAC-SHA256 - SHA256 based MAC
 * For TLS protocols (TLS, DTLS and QUIC): dynamic certificate creating or load them from files
 * Dynamic address assigments (both IPv4&IPv6) [plans]
 * Works on Linux and Windows
