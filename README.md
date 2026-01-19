# Let's Encrypt Certificate Manager

A Ruby tool for managing Let's Encrypt certificates for internal hosts using DNS-based validation.

## Features

- DNS-01 challenge validation (works for internal/private hosts)
- Cloudflare and Dreamhost DNS API support
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
./cert_manager.rb renew           # Renew certificates due for renewal
./cert_manager.rb --force renew   # Force renew all certificates
```

## CLI Reference

```
Usage: cert_manager.rb [options] <command>

Commands:
  request <name>    Request a new certificate
  renew             Renew certificates due for renewal
  list              List all configured certificates
  verify            Verify DNS provider credentials
  init              Create sample configuration file

Options:
  -c, --config PATH    Path to configuration file
  -s, --staging        Use staging environment (test certificates)
  -p, --production     Use production environment (real certificates)
  -n, --dry-run        Preview without making changes
  -f, --force          Force renewal even if not due
  -q, --quiet          Quiet mode (errors only)
  -y, --yes            Skip confirmation prompts
  -h, --help           Show help
```

## DNS Provider Setup

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
