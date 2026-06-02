# USSH

USSH is a shell protocol and client/server pair built from scratch on top of the existing UDP + AEAD transport.

It is not a TCP tunnel and does not wrap SSH inside TCP.

## Default port
- `5322`

## Server
```bash
python3 ussh_server.py \
  --peer-ip <CLIENT_IP_OR_DOMAIN> \
  --peer-port 0 \
  --bind-ip 0.0.0.0 \
  --bind-port 5322 \
  --psk "YOUR_SHARED_SECRET" \
  --cipher chacha20
```

## Client
```bash
python3 ussh_client.py \
  --peer-ip <SERVER_IP_OR_DOMAIN> \
  --peer-port 5322 \
  --bind-ip 0.0.0.0 \
  --bind-port 0 \
  --psk "YOUR_SHARED_SECRET" \
  --cipher chacha20
```

## Notes
- Transport stays UDP.
- Payloads are encrypted per packet with AEAD.
- The server launches a real PTY-backed shell.
- The client sends stdin bytes and renders stdout bytes.
