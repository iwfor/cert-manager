# Let's Encrypt Certificate Manager

A Ruby tool for managing Let's Encrypt certificates for internal hosts using DNS-based validation.

## Features

- DNS-01 challenge validation (works for internal/private hosts)
- Multiple DNS provider support:
  - Cloudflare
  - Dreamhost
  - AWS Route 53
  - GCP Cloud DNS
  - DNS Made Easy
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

## DNS Provider Setup

* Cloudflare - tested working
* Dreamhost - tested working
* AWS Route 53 - to be tested
* GCP Cloud DNS - to be tested
* DNS Made Easy - to be tested

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

---

Built with the assistance of AI (Claude by Anthropic).
