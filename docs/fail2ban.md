# fail2ban

LightBWS writes one warning line for every refused login, so [fail2ban](https://github.com/fail2ban/fail2ban) can ban addresses that keep guessing. This covers the Web UI login and the access-token exchange used by the SDK and `bws` (`/identity/connect/token`).

```text
2026-10-25T11:30:00.123456Z  WARN lightbws::auth: web login failed ip=203.0.113.7 reason=invalid_credentials username="admin"
2026-10-25T11:30:04.654321Z  WARN lightbws::auth: machine login failed ip=203.0.113.7 reason=invalid_credentials client_id="0b3f..."
```

`reason` is `invalid_credentials` or `rate_limited` (the built-in limit of 8 failures per username and address per minute was hit). Wrong usernames, wrong passwords and disabled accounts all log the same `invalid_credentials` reason. The address is always the first field, and client-supplied values are quoted and escaped, so a crafted username cannot make the filter ban someone else's address. The format is a stable interface for this filter.

## 1. Log the real client address

Behind a reverse proxy, LightBWS sees the proxy's address on every request. Set `LIGHTBWS_IP_HEADER` to the header your proxy sets with the client address:

| Proxy | Setting |
| --- | --- |
| nginx with `proxy_set_header X-Real-IP $remote_addr;` | `LIGHTBWS_IP_HEADER=X-Real-IP` |
| Caddy, Traefik | `LIGHTBWS_IP_HEADER=X-Forwarded-For` |
| Cloudflare in front of your proxy | `LIGHTBWS_IP_HEADER=CF-Connecting-IP` |

For a comma-separated list such as `X-Forwarded-For`, LightBWS uses the last entry, which is the one added by the proxy closest to LightBWS. Earlier entries are ignored because the client can forge them.

Only set `LIGHTBWS_IP_HEADER` when every request reaches LightBWS through that proxy. A client that can connect to LightBWS directly can send any value in the header. The documented Docker setup binds the port to `127.0.0.1`, which keeps the proxy the only way in. Leave it unset when LightBWS is not behind a proxy.

The address is also used for the built-in login rate limit, so setting the header stops one guessing client from locking out everyone behind the same proxy.

## 2. Give fail2ban the log

Pick one source.

**Log file.** Set `LIGHTBWS_LOG_FILE` to a path, and LightBWS writes a plain-text copy of its log there, in addition to standard output. The file is opened in append mode, so rotate it with `logrotate`'s `copytruncate` option. With Docker Compose, mount a host directory that the container user (UID 65532) can write:

```yaml
# docker-compose.override.yml
services:
  lightbws:
    environment:
      LIGHTBWS_LOG_FILE: /logs/lightbws.log
    volumes:
      - /var/log/lightbws:/logs
```

```sh
sudo install -d -o 65532 -g 65532 /var/log/lightbws
```

**journald.** For a systemd service, or Docker with the `journald` log driver (the default on NixOS), use `backend = systemd` with a `journalmatch` instead of `logpath`. The filter accepts the host and process prefix that journald adds.

Docker's default `json-file` driver wraps every line in JSON and escapes the quotes, so use the log file or the `journald` driver instead.

LightBWS only writes color codes when standard output is a terminal, so `docker logs`, journald and the log file hold plain text.

## 3. Install the filter and jail

```sh
sudo cp contrib/fail2ban/filter.d/lightbws.conf /etc/fail2ban/filter.d/
sudo cp contrib/fail2ban/jail.d/lightbws.local /etc/fail2ban/jail.d/
# Edit /etc/fail2ban/jail.d/lightbws.local for your log source, then:
sudo fail2ban-regex /var/log/lightbws/lightbws.log /etc/fail2ban/filter.d/lightbws.conf
sudo systemctl reload fail2ban
sudo fail2ban-client status lightbws
```

When a reverse proxy on the same host terminates HTTPS, the default action bans the address in the `INPUT` chain, which covers ports 80 and 443. When Docker publishes LightBWS's port directly, Docker's forwarded traffic bypasses `INPUT`; use `action = iptables-allports[name=lightbws, chain=DOCKER-USER]` as shown in the jail file.

A machine account whose access token was revoked or has expired fails on every retry, so a misconfigured SDK client or CI job can get its own address banned. Add trusted networks to `ignoreip` if that is a risk.

## NixOS

```nix
services.fail2ban = {
  enable = true;
  jails.lightbws.settings = {
    enabled = true;
    filter = "lightbws";
    backend = "systemd";
    journalmatch = "CONTAINER_NAME=lightbws"; # or "_SYSTEMD_UNIT=lightbws.service"
    port = "80,443";
    maxretry = 5;
    findtime = "10m";
    bantime = "1h";
  };
};
environment.etc."fail2ban/filter.d/lightbws.conf".source = ./lightbws.conf;
```
