# Certificate Manager for Let's Encrypt

A Ruby tool for managing Let's Encrypt certificates for internal hosts using DNS-based validation.

## Features

<img src="logo.png" alt="Logo" width="128" height="128" align="right"/>

- DNS-01 challenge validation (works for internal/private hosts)
- Multiple DNS provider support:
  - Cloudflare
  - Dreamhost
  - AWS Route 53
  - GCP Cloud DNS
  - DNS Made Easy
  - DigitalOcean
  - Linode (Akamai)
  - Namecheap
- DNS alias support for hosts without public DNS
- Provider/zone management from the command line, API keys encrypted at rest
- bash and zsh completions
- Staging and production environments
- Cron-friendly for automated renewals

## Requirements

- Ruby 2.7+
- [Certbot](https://certbot.eff.org/) installed and in PATH
- API credentials for your DNS provider

## Installation

1. Clone or copy files to your preferred location
2. Make the script executable:
   ```bash
   chmod +x cert_manager.rb
   ```
3. Create the configuration and encryption key:
   ```bash
   ./cert_manager.rb init --email admin@example.com
   ```
4. Add your DNS provider (the API key is asked for with a hidden prompt and stored encrypted):
   ```bash
   ./cert_manager.rb add-provider cloudflare --type cloudflare --zone example.com
   ```
5. Add certificates to `~/.config/cert_manager/config.v2.yml`, then enable
   [shell completions](#shell-completions).

Upgrading from the old `config.yml`? See [Migrating from v1](#migrating-from-v1).

## Configuration

Files live in `~/.config/cert_manager/` (override with `-c PATH` or `$CERT_MANAGER_CONFIG`):

| File | Purpose |
|------|---------|
| `config.v2.yml` | Providers, zones, certificates (mode `0600`) |
| `cert-manager.key` | Key that encrypts the API keys in the config (mode `0600`) |

Providers and zones are managed with commands (see [Managing providers and zones](#managing-providers-and-zones));
certificates and deploy targets are edited in the file:

```yaml
version: 2
email: admin@example.com

providers:
  cloudflare:
    type: cloudflare
    credentials:
      api_token: ENC[v1:...]      # written by add-provider, never typed by hand
    zones:
      - example.com

certificates:
  - name: myserver
    domains:
      - server.example.com        # served by the provider whose zone matches
```

A certificate is routed to the provider whose zone is the longest match for its
domains (all domains of one certificate must resolve to the same provider). To force a
provider, set `dns_provider: NAME` on the certificate.

For internal hosts that can't have public DNS records, use a DNS alias. Routing then
uses the alias' zone, since that is where the challenge record is placed:

```yaml
  - name: internal-host
    domains:
      - server.internal.local
    dns_alias: _acme-challenge.acme.example.com
```

To reuse the existing private key on renewal (useful for DANE/TLSA or key pinning):

```yaml
  - name: pinned-server
    domains:
      - server.example.com
    reuse_key: true
```

### Custom directories

By default, certificates are stored in `~/.local/share/certbot` (no root required). To customize:

```yaml
config_dir: /path/to/certbot/config   # certificates in config_dir/live
work_dir: /path/to/certbot/work
logs_dir: /path/to/certbot/logs
```

## Managing providers and zones

```bash
./cert_manager.rb add-provider NAME --type TYPE [--zone ZONE]...   # add a provider
./cert_manager.rb update-provider-key NAME                         # replace its API key
./cert_manager.rb add-zone NAME example.net                        # let it serve another zone
./cert_manager.rb remove-zone NAME example.net
./cert_manager.rb remove-provider NAME
./cert_manager.rb list-providers                                   # secrets are never shown
./cert_manager.rb help add-provider                                # every command has help
```

Secret values are never taken from the command line (they would show up in `ps` and shell
history). They come from a hidden prompt, from stdin (`--key-stdin`, one line per secret), or
from an environment variable (`--key-env VAR`, for a single secret):

```bash
./cert_manager.rb update-provider-key cloudflare --key-env NEW_CF_TOKEN
pass show cloudflare/token | ./cert_manager.rb update-provider-key cloudflare --key-stdin
```

Changes are verified against the provider API before they are saved (`--no-verify` to skip,
`--dry-run` to preview). `remove-zone` and `remove-provider` refuse if a certificate would be left
without a provider unless you pass `--force`. Each change keeps a timestamped `.bak` of the previous file.
Comments in `config.v2.yml` are not preserved when the tool rewrites it.

Providers tied to a single zone (Route 53 `hosted_zone_id`, Cloud DNS `managed_zone`, or Cloudflare
with `zone_id` set) serve exactly one zone; add another provider entry for each additional zone.

## Security model

- API keys and other secrets are encrypted in `config.v2.yml` (AES-256-GCM) as `ENC[v1:...]` values, using the
  random key in `cert-manager.key`. The key file is created with mode `0600`; the tool refuses to use it
  if group or others can read it.
- This protects the config when it is copied, committed, pasted into a ticket or included in a backup
  without the key. It does **not** protect against another process running as the same user, since the key
  sits next to the config. Back up `cert-manager.key` separately; without it the encrypted values cannot be recovered
  (re-enter them with `update-provider-key`).
- Plaintext secrets written by hand are still accepted with a warning and are encrypted the next time the tool rewrites the file.
- `list-providers`, dry runs and `test_dns_provider.rb -v` mask secrets.

## Migrating from v1

The old `config.yml` format (plaintext keys, `dns_provider` on every certificate) still works but prints a
deprecation notice on every run. Convert it with:

```bash
./cert_manager.rb convert-config --dry-run   # preview; secrets are masked
./cert_manager.rb convert-config             # writes config.v2.yml and cert-manager.key
./cert_manager.rb verify                     # confirm the new config works
```

The conversion encrypts every API key, infers each provider's zones from your certificates, and drops
`dns_provider` from certificates that zone routing resolves to the same provider. Certificates whose
zone is shared with another provider keep an explicit `dns_provider`. Your old file is never modified;
once `verify` passes, delete or archive it (it still contains plaintext keys). `config.v2.yml` takes
precedence over `config.yml` when both exist.

## Shell completions

Completions for bash and zsh are generated from the command definitions, so they always match the installed version:

```bash
eval "$(./cert_manager.rb completions)"          # shell taken from $SHELL
./cert_manager.rb completions zsh                # or choose: bash | zsh
```

Add the `eval` line to `~/.bashrc`, or to `~/.zshrc` after `compinit`. For zsh you can instead save the output
as `_cert_manager.rb` in a directory on your `$fpath`. Certificate, provider and zone names are completed
from your configuration (honoring `-c`). Use `--program NAME` if you invoke the tool under another name.

### 1. Test with staging first

Always test with staging to verify your DNS configuration:

```bash
./cert_manager.rb --staging request myserver
```

Staging certificates aren't trusted by browsers but don't count against rate limits.

### 2. Request production certificate

Once staging succeeds, request the real certificate:

```bash
./cert_manager.rb --production request myserver
```

If certbot refuses with "Certificate not yet due for renewal; no action
taken" (e.g. you already have a valid cert under this name for the same
domains, from a staging test or an earlier run), add `--force` to make
certbot reissue anyway:

```bash
./cert_manager.rb --force --production request myserver
```

### Other commands

```bash
./cert_manager.rb list              # Show all certificates and status
./cert_manager.rb verify            # Test DNS provider credentials
./cert_manager.rb --dry-run request myserver  # Preview without changes
```

## Automating Renewals

The `renew` command checks all certificates and renews those expiring within 30 days.

### Cron setup

Add to crontab (`crontab -e`):

```cron
# Run daily at 2am
0 2 * * * /path/to/cert_manager.rb --quiet --yes renew
```

Flags:
- `--quiet` - Only output errors (no info messages)
- `--yes` - Skip confirmation prompts

### Manual renewal

```bash
./cert_manager.rb renew              # Renew all certificates due for renewal
./cert_manager.rb renew myserver     # Renew specific certificate if due
./cert_manager.rb --force renew      # Force renew all certificates
./cert_manager.rb --force renew myserver  # Force renew specific certificate
```

## Deploying Certificates

Certificates can be automatically deployed after being requested or renewed.
Add a `deploy` section to any certificate in your config:

```yaml
certificates:
  - name: myserver
    domains:
      - server.example.com
    deploy:
      - user: deploy
        host: web1.example.com
        path: /etc/ssl/certs/myserver.crt
        key_path: /etc/ssl/private/myserver.key
        service: nginx
        action: reload
```

### Deploy target options

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `service` | yes | — | Service type: `nginx`, `apache`, or `copy` |
| `path` | yes | — | Destination for the certificate (fullchain.pem) |
| `user` | remote | — | SSH user for remote deploys |
| `host` | remote | — | SSH host for remote deploys |
| `local` | no | `false` | Set `true` to deploy on the local machine (no SSH) |
| `key_path` | no | — | Separate destination for the private key (`0600` permissions) |
| `append_key` | no | `false` | Append the private key to the cert file for a combined PEM |
| `action` | no | `reload` | `reload` or `restart` (ignored for `copy`) |
| `service_name` | no | varies | Override the systemd unit name (see service types below) |
| `sudo` | no | `true` | Set `false` to run commands without `sudo` |
| `custom_command` | no | — | Arbitrary command to run after copying (`copy` service only) |

### Service types

- **`nginx`** — reloads/restarts the `nginx` systemd unit
- **`apache`** — reloads/restarts the `apache2` systemd unit. Set `service_name: httpd` on RHEL/CentOS distributions
- **`copy`** — copies files only, with no service restart. Use `custom_command` to run your own reload logic

### Local deploy

Deploy certificates on the same machine without SSH. Omit `user` and `host`:

```yaml
deploy:
  - local: true
    path: /etc/ssl/certs/myserver.crt
    key_path: /etc/ssl/private/myserver.key
    service: nginx
    sudo: false    # useful when running as root
```

### Combined PEM file

Some services (e.g., HAProxy) require the certificate and private key in a
single file. Use `append_key` to append the key after the certificate:

```yaml
deploy:
  - user: deploy
    host: lb1.example.com
    path: /etc/haproxy/certs/myserver.pem
    append_key: true
    service: copy
    custom_command: sudo systemctl reload haproxy
```

You can use `append_key` together with `key_path` to deploy the key to both
the combined file and a separate location.

### Custom command

For services not managed by systemd, use the `copy` service type with
`custom_command`:

```yaml
deploy:
  - user: deploy
    host: proxy.example.com
    path: /etc/ssl/certs/myserver.crt
    key_path: /etc/ssl/private/myserver.key
    service: copy
    custom_command: sudo /usr/local/bin/reload-proxy
```

On remote targets, the command runs via SSH. On local targets, it runs directly.

### SSH and sudo

- Remote deploys upload files to `/tmp` first, then install with `cp`
- SSH runs in batch mode (no interactive password prompts)
- By default, `cp`, `chmod`, and `systemctl` are run with `sudo`
- Set `sudo: false` when running as root or when target paths are user-writable

Example sudoers entry for the deploy user:

```
deploy ALL=(ALL) NOPASSWD: /usr/bin/cp, /usr/bin/chmod, /usr/bin/systemctl
```

### Manual deploy

To deploy a certificate without requesting or renewing:

```bash
./cert_manager.rb deploy myserver
./cert_manager.rb --dry-run deploy myserver  # preview
```

### Failed deploy retry

If a target host is unreachable during deployment, the failure is recorded in
`config_dir/deploy_state.json` and deployment continues to the next target.
Failed deploys are retried automatically at the start of every `renew` run,
so a temporarily-down server gets its certificate deployed on the next daily
cron cycle.

Use `list` to see any pending deploy failures:

```bash
./cert_manager.rb list
```

Failed targets show the timestamp and error message:

```
  Deploy targets:
    - deploy@web1:/etc/ssl/certs/myserver.crt (reload nginx) DEPLOY FAILED
      Last failure: 2026-02-15T10:30:00Z
      Error: Failed to upload certificate to deploy@web1 (exit code: 255)
```

## Revoking Certificates

To revoke a certificate (e.g., if the private key was compromised):

```bash
./cert_manager.rb revoke myserver
```

Optionally specify a reason:

```bash
./cert_manager.rb revoke myserver --reason keycompromise
```

Valid reasons: `unspecified`, `keycompromise`, `affiliationchanged`, `superseded`, `cessationofoperation`

## Cleaning Up DNS Records

If a certificate request fails or is interrupted, ACME challenge TXT records may be left in DNS. To remove them:

```bash
./cert_manager.rb cleanup myserver
```

This finds and removes all `_acme-challenge` TXT records for the certificate's domains.

## CLI Reference

Run `cert_manager.rb help` for the full list and `cert_manager.rb help COMMAND` (or `COMMAND --help`) for details,
options and examples of a command. Global flags may be placed before or after the command.

```
Certificate commands:
  request <name>   Request a new certificate
  deploy <name>    Deploy a certificate to its configured targets
  renew [name]     Renew certificate(s) due for renewal
  revoke <name>    Revoke a certificate
  cleanup <name>   Remove leftover ACME challenge DNS records
  list             List configured certificates and their status

Configuration commands:
  verify                          Verify DNS provider credentials
  init                            Create a new configuration file and encryption key
  convert-config                  Convert a v1 config.yml to the v2 format
  add-provider <name>             Add a DNS provider (encrypts its API key)
  update-provider-key <provider>  Replace a provider's API key
  add-zone <provider> <zone>      Let a provider serve a DNS zone
  remove-zone <provider> <zone>   Stop a provider serving a DNS zone
  remove-provider <provider>      Remove a DNS provider and its stored credentials
  list-providers                  List providers, their zones and credential status

Tools:
  completions [shell]             Print a shell completion script (bash or zsh)
  help [command]                  Show help for a command

Global options:
  -c, --config PATH  Configuration file (default: $CERT_MANAGER_CONFIG, then config.v2.yml, then config.yml)
  -n, --dry-run      Show what would be done without making changes
  -f, --force        Reissue even if not due (request/renew); clear recorded failure state (deploy)
  -s, --staging      Use Let's Encrypt staging (test certificates)
  -p, --production   Use Let's Encrypt production (real certificates)
  -q, --quiet        Only output errors (for cron jobs)
  -y, --yes          Skip confirmation prompts (for automation)
  -v, --verbose      Show extra detail
  -V, --version      Show version
  -h, --help         Show help
```

Exit status: `0` success, `1` error, `2` usage error (bad command line). Errors are written to stderr.
`verify` exits non-zero when a provider rejects its credentials.

## Testing DNS Providers

After configuring a DNS provider (see [DNS Provider Setup](#dns-provider-setup) below), use `test_dns_provider.rb` to verify that the API credentials are working before requesting certificates. It creates a temporary TXT record, verifies it via DNS lookup and API query, then removes it — all without involving certbot.

### Basic test

Assuming your config has a provider named `cloudflare_dns`:

```bash
./test_dns_provider.rb -p cloudflare_dns -d example.com
```

This runs four tests against the provider named `cloudflare_dns` in your config:

1. **Add** a test TXT record (`_acme-challenge-test.example.com`)
2. **Verify** the record via DNS lookup (waits 10 seconds for propagation)
3. **Find** the record via the provider's API
4. **Remove** the record and confirm deletion

### Options

| Flag | Description |
|------|-------------|
| `-p, --provider NAME` | Provider name from config (required) |
| `-d, --domain DOMAIN` | Domain to test with (required for add/remove) |
| `-c, --config PATH` | Config file path (default: same lookup as `cert_manager.rb`) |
| `-k, --keep` | Keep the test record instead of deleting it |
| `-l, --list` | List existing DNS records only (requires `-d`) |
| `-w, --wait SECONDS` | Seconds to wait for DNS propagation (default: 10) |
| `-v, --verbose` | Show verbose output including stack traces |

### List existing records

Some providers support listing all DNS records for a domain:

```bash
./test_dns_provider.rb -p cloudflare_dns -d example.com --list
```

### Troubleshooting

If the DNS verification step reports "Record not found", the record may need more propagation time. Try increasing the wait with `-w 30`. The API-level find test (test 3) will confirm whether the record was actually created.

## DNS Provider Setup

Secrets (API keys and tokens) are asked for with a hidden prompt when you add a provider; see
[Managing providers and zones](#managing-providers-and-zones) for the other ways to supply them.

* Cloudflare - tested working
* Dreamhost - tested working
* AWS Route 53 - to be tested
* GCP Cloud DNS - to be tested
* DNS Made Easy - to be tested
* DigitalOcean - to be tested
* Linode (Akamai) - to be tested
* Namecheap - to be tested

### Cloudflare

1. Go to https://dash.cloudflare.com/profile/api-tokens
2. Create a token with **Zone.DNS Edit** permission
3. Add the provider:
   ```bash
   ./cert_manager.rb add-provider cloudflare --type cloudflare --zone example.com
   ```

### Dreamhost

1. Go to https://panel.dreamhost.com/index.cgi?tree=home.api
2. Create a key with **dns-\*** permissions
3. Add the provider:
   ```bash
   ./cert_manager.rb add-provider dreamhost --type dreamhost --zone example.org
   ```

### AWS Route 53

1. Install the AWS SDK: `gem install aws-sdk-route53`
2. Get your Hosted Zone ID from the Route 53 console
3. Create an IAM user/role with `route53:ChangeResourceRecordSets` and `route53:ListResourceRecordSets` permissions
4. Add the provider:
   ```bash
   ./cert_manager.rb add-provider route53 --type route53 --set hosted_zone_id=Z1234567890ABC --zone example.com
   ```

   To use explicit keys instead of the AWS credential chain, also pass the key id, then store the secret key:
   ```bash
   ./cert_manager.rb add-provider route53 --type route53 --set hosted_zone_id=Z1234567890ABC --set access_key_id=AKIA... --zone example.com
   ./cert_manager.rb update-provider-key route53 --credential secret_access_key
   ```

If you don't provide credentials, the AWS SDK will use the standard credential chain:
- Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
- Shared credentials file (`~/.aws/credentials`)
- IAM role (on EC2/ECS/Lambda)

### GCP Cloud DNS

1. Install the Google Cloud SDK: `gem install google-apis-dns_v1 googleauth`
2. Create a Cloud DNS managed zone or note your existing zone name
3. Create a service account with **DNS Administrator** role
4. Add the provider:
   ```bash
   ./cert_manager.rb add-provider gcp_dns --type cloud_dns --set project_id=my-project-123 --set managed_zone=my-zone-name --set credentials_file=/path/to/service-account.json --zone example.com
   ```

If you don't provide `credentials_file`, the SDK uses Application Default Credentials:
- `GOOGLE_APPLICATION_CREDENTIALS` environment variable
- Default service account (on GCE/GKE/Cloud Run)
- User credentials from `gcloud auth application-default login`

### DNS Made Easy

1. Log in to your DNS Made Easy account
2. Go to **Account** → **API Credentials**
3. Generate an API key and Secret key
4. Add the provider:
   ```bash
   ./cert_manager.rb add-provider dnsmadeeasy --type dnsmadeeasy --zone example.com   # prompts for api_key, then secret_key
   ```

Optional: add `--set sandbox=true` to test against the DNS Made Easy sandbox environment.

### DigitalOcean

1. Go to https://cloud.digitalocean.com/account/api/tokens
2. Create a personal access token with **read/write** scope
3. Add the provider:
   ```bash
   ./cert_manager.rb add-provider digitalocean --type digitalocean --zone example.com
   ```

### Linode (Akamai)

1. Go to https://cloud.linode.com/profile/tokens
2. Create a personal access token with **Domains: Read/Write** scope
3. Add the provider:
   ```bash
   ./cert_manager.rb add-provider linode --type linode --zone example.com
   ```

### Namecheap

1. Enable API access at https://www.namecheap.com/support/api/intro/
2. Whitelist your IP address in the API access settings
3. Note your API key and username
4. Add the provider:
   ```bash
   ./cert_manager.rb add-provider namecheap --type namecheap --set api_user=your-username --set client_ip=1.2.3.4 --zone example.com
   ```

Note: `client_ip` must match an IP whitelisted in your Namecheap API settings.

---

Built with the assistance of AI (Claude by Anthropic).
