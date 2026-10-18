# USAGE

This document covers configuring CertManager for new sites, deploying certificates to your infrastructure, and scheduling automated daily renewals with crontab on Linux and macOS.

---

## Configuring a New Site

### 1. Initialize the configuration

```bash
./cert_manager.rb init --email admin@example.com
```

This creates `~/.config/cert_manager/config.v2.yml` and the encryption key `cert-manager.key` next to it (both mode `0600`).
Coming from the old `config.yml`? Run `./cert_manager.rb convert-config` instead; see [Migrating from v1](#migrating-from-v1).

### 2. Add a DNS provider and its zones

```bash
./cert_manager.rb add-provider cloudflare_dns --type cloudflare --zone mysite.com
```

You are asked for the API token with a hidden prompt; it is verified against the provider and stored encrypted.
See [DNS Provider Setup](#dns-provider-setup) below for what each provider needs. Zones can be changed later with
`add-zone` / `remove-zone`, and a key replaced with `update-provider-key`.

### 3. Add a certificate entry

Under `certificates` in `config.v2.yml`, add a block for each site. The minimum required fields:

```yaml
certificates:
  - name: mysite
    domains:
      - www.mysite.com
```

The provider is chosen automatically: it is the one with the longest zone matching the domains (here `mysite.com`).
Add `dns_provider: NAME` to a certificate to force a specific provider.

### 4. Test with staging

Before requesting a production certificate, test your DNS configuration with the staging environment:

```bash
./cert_manager.rb --staging request mysite
```

Staging certificates are not trusted by browsers but let you verify the full flow without using rate limits.

### 5. Request the production certificate

Once staging succeeds:

```bash
./cert_manager.rb --production request mysite
```

If certbot refuses with "Certificate not yet due for renewal; no action
taken" — for example because a valid cert already exists under this name
for the same domains (from the staging test above, if it reused the same
cert name) — add `--force` to make certbot reissue anyway:

```bash
./cert_manager.rb --force --production request mysite
```

### 6. Verify the result

```bash
./cert_manager.rb list
```

---

## DNS Provider Setup

Each provider is added with `add-provider NAME --type TYPE`. Secrets are asked for with a hidden prompt (or supplied with
`--key-stdin` / `--key-env VAR`; never as command-line arguments). Non-secret settings are passed with `--set KEY=VALUE`.

| Provider | `--type` | Prompted secrets | Non-secret settings (`--set`) | Notes |
| -------- | -------- | ---------------- | ----------------------------- | ----- |
| Cloudflare | `cloudflare` | `api_token` | `zone_id` (optional; pins the provider to one zone) | Token from https://dash.cloudflare.com/profile/api-tokens with **Zone.DNS Edit** |
| Dreamhost | `dreamhost` | `api_key` | | Key from https://panel.dreamhost.com/index.cgi?tree=home.api with **dns-\*** permissions |
| AWS Route 53 | `route53` | none (`secret_access_key` optional) | `hosted_zone_id` (required), `access_key_id`, `region` | `gem install aws-sdk-route53`; without keys the SDK credential chain is used. Serves one zone. Add the optional secret with `update-provider-key NAME --credential secret_access_key` |
| GCP Cloud DNS | `cloud_dns` | none | `project_id`, `managed_zone` (required), `credentials_file` | `gem install google-apis-dns_v1 googleauth`; uses Application Default Credentials without `credentials_file`. Serves one zone |
| DNS Made Easy | `dnsmadeeasy` | `api_key`, then `secret_key` | `sandbox=true` | Credentials from https://dnsmadeeasy.com/ account settings |
| DigitalOcean | `digitalocean` | `api_token` | | Token with **read/write** scope: https://cloud.digitalocean.com/account/api/tokens |
| Linode (Akamai) | `linode` | `api_token` | | Token with **Domains: Read/Write**: https://cloud.linode.com/profile/tokens |
| Namecheap | `namecheap` | `api_key` | `api_user`, `client_ip` (required) | Enable API access and whitelist your IP: https://www.namecheap.com/support/api/intro/ |

Examples:

```bash
./cert_manager.rb add-provider cloudflare_dns --type cloudflare --zone example.com --zone example.net
./cert_manager.rb add-provider aws --type route53 --set hosted_zone_id=Z1234567890ABC --zone example.org
./cert_manager.rb add-provider nc --type namecheap --set api_user=me --set client_ip=1.2.3.4 --zone example.io
./cert_manager.rb update-provider-key cloudflare_dns --key-env NEW_CF_TOKEN
./cert_manager.rb list-providers
```

---

## DNS Alias (Internal Hosts)

When a domain cannot have public DNS records (e.g. `server.internal.local`), use a DNS alias. The ACME challenge TXT record is published to the alias domain, and you create a CNAME from the original domain pointing to the alias:

```yaml
certificates:
  - name: internal-server
    domains:
      - server.internal.local
    dns_alias: _acme-challenge.acme.example.com
```

The provider is selected by the zone of the alias (`acme.example.com`), because that is where the TXT record is created.

Then in your public DNS for `acme.example.com`:

```
_acme-challenge.server.internal.local. CNAME _acme-challenge.acme.example.com.
```

---

## Deployment Types

CertManager supports four deployment strategies after a certificate is obtained or renewed. Add a `deploy` block to any certificate entry.

### Remote deployment (SSH)

Deploy to a remote host via scp/ssh. Files are uploaded to `/tmp` then installed into place with verification.

```yaml
certificates:
  - name: myserver
    domains:
      - www.example.com
    deploy:
      - user: deploy
        host: web1.example.com
        path: /etc/ssl/certs/www.example.com.crt
        key_path: /etc/ssl/private/www.example.com.key
        service: nginx
        action: reload
```

**Remote options:**

| Option           | Required | Description                                                                 |
| ---------------- | -------- | --------------------------------------------------------------------------- |
| user             | yes      | SSH username                                                                |
| host             | yes      | SSH hostname                                                                |
| path             | yes      | Destination for `fullchain.pem`                                             |
| key_path         | no       | Separate destination for `privkey.pem` (permissions set to `0600` auto)     |
| service          | yes      | Service type: `nginx`, `apache`, or `copy`                                  |
| service_name     | no       | Override systemd unit name (e.g. `httpd` on RHEL/CentOS)                    |
| action           | no       | `reload` (default) or `restart`. Ignored for `copy`                         |
| sudo             | no       | `true` (default) or `false` to skip sudo                                    |
| custom_command   | no       | Arbitrary command to run after copying (only with `service: copy`)          |

### Local deployment

Deploy on the same machine the script runs on. Omit `user` and `host`; set `local: true`.

```yaml
certificates:
  - name: local-server
    domains:
      - local.example.com
    deploy:
      - local: true
        path: /etc/ssl/certs/local.example.com.crt
        key_path: /etc/ssl/private/local.example.com.key
        service: nginx
        sudo: false
```

### Combined PEM file (e.g., HAProxy)

Append the private key to the certificate file for services that require a combined PEM:

```yaml
certificates:
  - name: haproxy-server
    domains:
      - ha.example.com
    deploy:
      - user: deploy
        host: lb1.example.com
        path: /etc/haproxy/certs/ha.example.com.pem
        append_key: true
        service: copy
        custom_command: sudo systemctl reload haproxy
```

### Custom command (non-systemd services)

For services not managed by systemd, use `service: copy` with a `custom_command`:

```yaml
certificates:
  - name: custom-service
    domains:
      - custom.example.com
    deploy:
      - user: deploy
        host: proxy.example.com
        path: /etc/ssl/certs/custom.example.com.crt
        key_path: /etc/ssl/private/custom.example.com.key
        service: copy
        custom_command: sudo /usr/local/bin/reload-proxy
```

### Multiple deploy targets

A single certificate can be deployed to multiple hosts:

```yaml
certificates:
  - name: shared-cert
    domains:
      - www.example.com
    deploy:
      - host: web1.example.com
        user: deploy
        path: /etc/ssl/certs/www.example.com.crt
        service: nginx
      - host: web2.example.com
        user: deploy
        path: /etc/ssl/certs/www.example.com.crt
        service: nginx
      - host: web3.example.com
        user: deploy
        path: /etc/ssl/certs/www.example.com.crt
        service: nginx
```

### SSH sudoers

The deploy users need sudo access to `cp`, `chmod`, and `systemctl` on the target hosts. Add to the target's sudoers file (`/etc/sudoers.d/deploy`):

```
deploy ALL=(ALL) NOPASSWD: /usr/bin/cp, /usr/bin/chmod, /usr/bin/systemctl
```

---

## Scheduling Daily Renewals with Crontab

CertManager checks if any certificate is expiring within 30 days. If so, it renews it. Schedule the `renew` command to run daily via crontab.

### On Linux

```bash
crontab -e
```

Add this line (runs daily at 2:00 AM):

```cron
0 2 * * * /path/to/cert_manager.rb --quiet --yes renew 2>&1
```

### On macOS

Crontab on macOS works the same way, but the path to cron may differ:

```bash
crontab -e
```

Add the same line:

```cron
0 2 * * * /path/to/cert_manager.rb --quiet --yes renew 2>&1
```

Ensure `certbot` is in the cron job's PATH. If certbot is installed via Homebrew but not found, use the full path:

```cron
0 2 * * * /opt/homebrew/bin/certbot && /usr/local/bin/ruby /path/to/cert_manager.rb --quiet --yes renew 2>&1
```

Or prepend PATH to the cron entry:

```cron
0 2 * * * PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin /path/to/cert_manager.rb --quiet --yes renew 2>&1
```

### Flags explained

| Flag      | Description                                                                 |
| --------- | --------------------------------------------------------------------------- |
| `--quiet` | Only outputs errors - suppresses routine info messages                      |
| `--yes`   | Skips all confirmation prompts (required for cron)                          |

The cron job must run as the user that owns `~/.config/cert_manager/`, because it needs to read `cert-manager.key`
to decrypt the API keys. If the config is elsewhere, set `CERT_MANAGER_CONFIG=/path/to/config.v2.yml` in the cron entry
(or pass `-c`) and keep `cert-manager.key` in the same directory. While you still use a v1 `config.yml`, every run prints a
deprecation notice to stderr, which cron will mail to you; that is your reminder to run `convert-config`.

### Verifying the cron job is running

Check the system cron log:

**Linux:**
```bash
grep cert_manager /var/log/syslog
grep cert_manager /var/log/cron
```

**macOS:**
```bash
grep cert_manager /var/log/system.log
```

Or redirect output to a log file:

```cron
0 2 * * * /path/to/cert_manager.rb --quiet --yes renew >> /path/to/cert_manager.log 2>&1
```

---

## Manual Operations

```bash
./cert_manager.rb list                   # Show all certificates and status
./cert_manager.rb deploy myserver        # Deploy a certificate without renewing
./cert_manager.rb renew                  # Renew all certificates due for renewal
./cert_manager.rb renew myserver         # Renew a specific certificate if due
./cert_manager.rb --force renew          # Force renew all certificates
./cert_manager.rb --staging request myserver   # Request a staging certificate
./cert_manager.rb --dry-run request myserver   # Preview without making changes
./cert_manager.rb verify                 # Test DNS provider credentials (non-zero exit on failure)
./cert_manager.rb cleanup myserver       # Remove leftover ACME challenge DNS records
./cert_manager.rb revoke myserver        # Revoke a certificate
./cert_manager.rb list-providers         # Providers, zones and credential status (no secrets shown)
./cert_manager.rb help add-provider      # Help for any command
```

---

## Migrating from v1

The old `config.yml` (plaintext keys, `dns_provider` on every certificate) still works but is deprecated.

```bash
./cert_manager.rb convert-config --dry-run   # preview the result; secrets are masked
./cert_manager.rb convert-config             # write config.v2.yml + cert-manager.key
./cert_manager.rb verify                     # check every provider with the new config
```

What the conversion does:

- Moves each provider's credentials under `credentials` and encrypts the secret ones (`ENC[v1:...]`).
- Infers each provider's `zones` from your certificates' domains (or `dns_alias` targets) and removes `dns_provider`
  from certificates that zone routing resolves to the same provider. Certificates whose zone is shared with another provider keep `dns_provider`.
- Copies `deploy` blocks, settings and everything else unchanged. Comments are not carried over.
- Leaves the old file untouched. After `verify` passes, delete or archive it, since it still holds plaintext keys.

Review the printed zones; use `add-zone` / `remove-zone` to adjust. Providers that no certificate used get no zones until you add some.
`--output PATH` chooses where the v2 file is written.

## Shell Completions

```bash
eval "$(./cert_manager.rb completions)"   # add to ~/.bashrc, or ~/.zshrc after compinit
./cert_manager.rb completions bash        # or: zsh (default comes from $SHELL)
```

Commands, flags, certificate names, provider names and zones are completed. They are generated from the command definitions, so they stay current as commands are added.

## The Encryption Key

`cert-manager.key` (next to the config, mode `0600`) encrypts every secret in `config.v2.yml`. Back it up somewhere other than
where you back up the config; if it is lost, re-enter the keys with `update-provider-key`. The tool refuses to read a key file that group or others can access
(`chmod 600` it). The key keeps the config safe to copy, commit or paste, but it does not defend against another process running as the same user.

---

## Appendix: Full Configuration Reference

| Top-level key      | Required | Description                                                                 |
| ------------------ | -------- | --------------------------------------------------------------------------- |
| email              | yes      | Let's Encrypt account email                                                 |
| environment        | no       | Default environment: `production` or `staging` (defaults to `production`)   |
| certbot_path       | no       | Full or path-relative path to the certbot binary                            |
| log_level          | no       | Log level: `DEBUG`, `INFO`, `WARN`, or `ERROR`                              |
| propagation_wait   | no       | Seconds to wait for DNS propagation (defaults to `60`)                      |
| config_dir         | no       | Directory for certbot certificates (defaults to `~/.local/share/certbot`)   |
| work_dir           | no       | Certbot working directory (defaults to `config_dir/work`)                   |
| logs_dir           | no       | Certbot log directory (defaults to `config_dir/logs`)                       |

| Certificate-level key  | Required | Description                                                                 |
| ---------------------- | -------- | --------------------------------------------------------------------------- |
| name                   | no       | Display name for the certificate (defaults to the first domain)             |
| domains                | yes      | List of domain names to include in the certificate                          |
| dns_provider           | no       | Force a provider by name; by default it is resolved from the providers' `zones` |
| dns_alias              | no       | DNS alias domain for the ACME challenge TXT record                          |
| environment            | no       | Override default: `staging` or `production`                                 |
| reuse_key              | no       | Reuse the existing private key on renewal (defaults to `true`)              |
| deploy                 | no       | List of deploy targets (see Deployment Types above)                         |

| Provider key (`providers.NAME`) | Required | Description                                                                 |
| ------------------------------- | -------- | --------------------------------------------------------------------------- |
| version (top level)             | yes      | Must be `2`                                                                 |
| type                            | yes      | Provider type (see DNS Provider Setup)                                      |
| credentials                     | yes      | Mapping of credential name to value; secrets are stored as `ENC[v1:...]`    |
| zones                           | no       | Zones this provider serves; certificates are routed by longest matching zone |

Manage these with `add-provider`, `update-provider-key`, `add-zone`, `remove-zone` and `remove-provider` rather than editing the file by hand.
