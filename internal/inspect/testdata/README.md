# Captured client hellos

Each `.hex` file is the first read off a socket, hex-encoded, from a real client asked to
reach `example.test` over TLS. They were captured against a plain TCP listener that accepts
one connection, reads once and writes what it read, so the bytes are exactly what the client
put on the wire and nothing has reassembled or normalised them.

| File | Client | Asked for |
|---|---|---|
| `clienthello-curl.hex` | curl 8.7.1 (macOS, LibreSSL 3.3.6) | `example.test`, default ALPN |
| `clienthello-go.hex` | Go 1.26.5 `crypto/tls` | `example.test`, ALPN `h2`, `http/1.1` |
| `clienthello-openssl.hex` | OpenSSL 3.6.3 `s_client` | `example.test`, ALPN `h2` |

The two large ones carry a post-quantum key share, which is what makes them span more than
one TLS record: they are the reason the window is four kilobytes and the reason the parser
walks records rather than reading one.
