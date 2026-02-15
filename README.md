# Certificate Manager for Let's Encrypt

A Ruby tool for managing Let's Encrypt certificates for internal hosts using DNS-based validation.

## Features

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
3. Initialize configuration:
   ```bash
   ./cert_manager.rb init
   ```
4. Edit `~/.config/cert_manager/config.yml` with your DNS credentials and certificates

## Configuration

Edit `~/.config/cert_manager/config.yml`:

```yaml
email: admin@example.com

dns_providers:
  cloudflare:
    type: cloudflare
    api_token: your-api-token

certificates:
  - name: myserver
    domains:
      - server.example.com
    dns_provider: cloudflare
```

For internal hosts that can't have public DNS records, use a DNS alias:

```yaml
  - name: internal-host
    domains:
      - server.internal.local
    dns_provider: cloudflare
    dns_alias: _acme-challenge.acme.example.com
```

To reuse the existing private key on renewal (useful for DANE/TLSA or key pinning):

```yaml
  - name: pinned-server
    domains:
      - server.example.com
    dns_provider: cloudflare
    reuse_key: true
```

### Custom directories

By default, certificates are stored in `~/.local/share/certbot` (no root required). To customize:

```yaml
config_dir: /path/to/certbot/config   # certificates in config_dir/live
work_dir: /path/to/certbot/work
logs_dir: /path/to/certbot/logs
```

## Requesting Certificates

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
    dns_provider: cloudflare
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

```
Usage: cert_manager.rb [options] <command>

Commands:
  request <name>    Request a new certificate
  deploy <name>     Deploy certificate to configured targets
  renew [name]      Renew certificate(s) due for renewal
  revoke <name>     Revoke a certificate
  cleanup <name>    Remove leftover ACME challenge DNS records
  list              List all configured certificates
  verify            Verify DNS provider credentials
  init              Create sample configuration file

Options:
  -c, --config PATH    Path to configuration file
  -s, --staging        Use staging environment (test certificates)
  -p, --production     Use production environment (real certificates)
  -n, --dry-run        Preview without making changes
  -f, --force          Force renewal even if not due
  -r, --reason REASON  Revocation reason (for revoke command)
  -q, --quiet          Quiet mode (errors only)
  -y, --yes            Skip confirmation prompts
  -h, --help           Show help
```

## Testing DNS Providers

After configuring a DNS provider in your `config.yml` (see [DNS Provider Setup](#dns-provider-setup) below), use `test_dns_provider.rb` to verify that the API credentials are working before requesting certificates. It creates a temporary TXT record, verifies it via DNS lookup and API query, then removes it — all without involving certbot.

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
| `-c, --config PATH` | Config file path (default: `~/.config/cert_manager/config.yml`) |
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
3. Add to config:
   ```yaml
   dns_providers:
     cloudflare:
       type: cloudflare
       api_token: your-token
   ```

### Dreamhost

1. Go to https://panel.dreamhost.com/index.cgi?tree=home.api
2. Create a key with **dns-\*** permissions
3. Add to config:
   ```yaml
   dns_providers:
     dreamhost:
       type: dreamhost
       api_key: your-key
   ```

### AWS Route 53

1. Install the AWS SDK: `gem install aws-sdk-route53`
2. Get your Hosted Zone ID from the Route 53 console
3. Create an IAM user/role with `route53:ChangeResourceRecordSets` and `route53:ListResourceRecordSets` permissions
4. Add to config:
   ```yaml
   dns_providers:
     route53:
       type: route53
       hosted_zone_id: Z1234567890ABC
       # Optional: explicit credentials
       access_key_id: AKIAIOSFODNN7EXAMPLE
       secret_access_key: your-secret-key
   ```

If you don't provide credentials, the AWS SDK will use the standard credential chain:
- Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
- Shared credentials file (`~/.aws/credentials`)
- IAM role (on EC2/ECS/Lambda)

### GCP Cloud DNS

1. Install the Google Cloud SDK: `gem install google-apis-dns_v1 googleauth`
2. Create a Cloud DNS managed zone or note your existing zone name
3. Create a service account with **DNS Administrator** role
4. Add to config:
   ```yaml
   dns_providers:
     gcp_dns:
       type: cloud_dns
       project_id: my-project-123
       managed_zone: my-zone-name
       # Optional: path to service account key
       credentials_file: /path/to/service-account.json
   ```

If you don't provide `credentials_file`, the SDK uses Application Default Credentials:
- `GOOGLE_APPLICATION_CREDENTIALS` environment variable
- Default service account (on GCE/GKE/Cloud Run)
- User credentials from `gcloud auth application-default login`

### DNS Made Easy

1. Log in to your DNS Made Easy account
2. Go to **Account** → **API Credentials**
3. Generate an API key and Secret key
4. Add to config:
   ```yaml
   dns_providers:
     dnsmadeeasy:
       type: dnsmadeeasy
       api_key: your-api-key
       secret_key: your-secret-key
   ```

Optional: Use `sandbox: true` to test against the DNS Made Easy sandbox environment.

### DigitalOcean

1. Go to https://cloud.digitalocean.com/account/api/tokens
2. Create a personal access token with **read/write** scope
3. Add to config:
   ```yaml
   dns_providers:
     digitalocean:
       type: digitalocean
       api_token: your-token
   ```

### Linode (Akamai)

1. Go to https://cloud.linode.com/profile/tokens
2. Create a personal access token with **Domains: Read/Write** scope
3. Add to config:
   ```yaml
   dns_providers:
     linode:
       type: linode
       api_token: your-token
   ```

### Namecheap

1. Enable API access at https://www.namecheap.com/support/api/intro/
2. Whitelist your IP address in the API access settings
3. Note your API key and username
4. Add to config:
   ```yaml
   dns_providers:
     namecheap:
       type: namecheap
       api_key: your-api-key
       api_user: your-username
       client_ip: 1.2.3.4
   ```

Note: `client_ip` must match an IP whitelisted in your Namecheap API settings.

---

Built with the assistance of AI (Claude by Anthropic).
