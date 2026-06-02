# USSH

USSH is a shell protocol and client/server pair built on top of USTP-Secure.

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

On interactive startup, the server asks whether it should install itself as a `systemd` service. Answer `n` to run it normally. Use `--no-systemd-prompt` to skip that question.

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
- Transport is USTP-Secure over UDP.
- Payloads are encrypted per packet with AEAD.
- The server launches a real PTY-backed shell on the machine running `ussh_server.py`.
- The client sends stdin bytes and renders stdout bytes.
