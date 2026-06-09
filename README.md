# USSH

USSH is a shell protocol and client/server pair built on top of USTP-Secure.

It is not a TCP tunnel and does not wrap SSH inside TCP.

Status: **Beta**

License: `MIT`

## Default port
- `5322`

## Server
```bash
python3 ussh_server.py \
  --peer-ip <CLIENT_IP_OR_DOMAIN> \
  --peer-port 0 \
  --bind-ip 0.0.0.0 \
  --bind-port 5322 \
  --cipher chacha20
```

If `--password` is omitted, the server prompts for the USSH login password on startup.

On interactive startup, the server asks whether it should install itself as a `systemd` service. Answer `n` to run it normally. Use `--no-systemd-prompt` to skip that question.

## Client
```bash
python3 ussh_client.py \
  --peer-ip <SERVER_IP_OR_DOMAIN> \
  --peer-port 5322 \
  --bind-ip 0.0.0.0 \
  --bind-port 0 \
  --cipher chacha20
```

The client prompts for the password interactively, like SSH.

The client stores the first seen server X25519 public key in `~/.ussh_known_hosts.json`.
If that key changes later, the client aborts with a TOFU mismatch error instead of silently trusting the new key.
If you intentionally rotated the server host key, run the client with `--regen-key` to allow replacing the stored TOFU key after interactive confirmation.

## Internet-Drafts
- `USSH` Internet-Draft: `https://datatracker.ietf.org/doc/draft-x1co-ussh/`

## Notes
- Transport is USTP-Secure over UDP.
- USTP-Secure does not implement congestion control; USSH inherits that speed-first behavior from the transport.
- USTP-Secure itself remains unordered.
- USSH does not turn the transport into an ordered TCP-like channel.
- USSH only reassembles the logical `stdout` byte stream before writing to the terminal.
- That reassembly exists because an interactive shell output is a continuous byte stream, and rendering terminal bytes in raw arrival order can corrupt large outputs such as `ls`, `find`, or compiler logs.
- This means USTP-Secure still avoids transport-level Head-of-Line blocking, while USSH restores only the application-level order required for terminal rendering.
- Payloads are encrypted per packet with AEAD.
- No static PSK is used.
- Each client receives a separate ephemeral AEAD session key through X25519.
- The password is used for USSH authentication after the secure session is established.
- The server launches a real PTY-backed shell on the machine running `ussh_server.py`.
- The client sends stdin bytes and renders stdout bytes.
- The server supports multiple clients, with one shell/session per client.
- If `--cipher` is set on the server, the server uses that exact cipher.
- If `--cipher` is omitted or set to `auto`, the server uses the cipher requested by the client.
- Clients reject unexpected cipher negotiation.
- TOFU (Trust On First Use) is enabled on the client to detect unexpected server key changes after the first connection.
- The server keeps a persistent X25519 host key in `~/.ussh_host_key` by default so TOFU remains stable across reconnects and restarts.
- A normal server restart does not change the host key.
- Use `--regen-key` on the server only when you intentionally want to rotate that host key.
- TOFU entries are stored per `<peer-ip-or-domain>:<peer-port>`, so a different server at a different address/port is treated as a different host identity.
