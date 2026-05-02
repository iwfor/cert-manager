# USAGE

This document covers configuring CertManager for new sites, deploying certificates to your infrastructure, and scheduling automated daily renewals with crontab on Linux and macOS.

---

## Configuring a New Site

### 1. Initialize the configuration file

```bash
./cert_manager.rb init
```

This creates `~/.config/cert_manager/config.yml`. Alternatively, copy `config.yml.example` and customize it.

### 2. Configure a DNS provider

Add at least one DNS provider under `dns_providers`. See [DNS Provider Setup](#dns-provider-setup) below for credential requirements.

### 3. Add a certificate entry

Under `certificates`, add a block for each site. The minimum required fields:

```yaml
certificates:
  - name: mysite
    domains:
      - www.mysite.com
    dns_provider: cloudflare_dns
```

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

### 6. Verify the result

```bash
./cert_manager.rb list
```

---

## DNS Provider Setup

### Cloudflare

1. Create a token at https://dash.cloudflare.com/profile/api-tokens with **Zone.DNS Edit** permission
2. Add to config:

```yaml
dns_providers:
  cloudflare_dns:
    type: cloudflare
    api_token: your-token
```

### Dreamhost

1. Create an API key at https://panel.dreamhost.com/index.cgi?tree=home.api with **dns-*** permissions
2. Add to config:

```yaml
dns_providers:
  dreamhost_dns:
    type: dreamhost
    api_key: your-api-key
```

### AWS Route 53

1. Install the AWS SDK: `gem install aws-sdk-route53`
2. Get your Hosted Zone ID from the Route 53 console
3. Create an IAM user/role with `route53:ChangeResourceRecordSets` and `route53:ListResourceRecordSets` permissions
4. Add to config:

```yaml
dns_providers:
  route53_dns:
    type: route53
    hosted_zone_id: Z1234567890ABC
```

If you omit `access_key_id` and `secret_access_key`, the SDK uses the standard credential chain (environment variables, `~/.aws/credentials`, or IAM role).

### GCP Cloud DNS

1. Install the gems: `gem install google-apis-dns_v1 googleauth`
2. Create a Cloud DNS managed zone or note your existing zone name
3. Create a service account with **DNS Administrator** role
4. Add to config:

```yaml
dns_providers:
  gcp_dns:
    type: cloud_dns
    project_id: my-project-123
    managed_zone: my-zone-name
    credentials_file: /path/to/service-account.json  # optional; uses ADC if omitted
```

### DNS Made Easy

1. Generate API credentials at https://dnsmadeeasy.com/ account settings
2. Add to config:

```yaml
dns_providers:
  dnsmadeeasy_dns:
    type: dnsmadeeasy
    api_key: your-api-key
    secret_key: your-secret-key
    # sandbox: true  # use the sandbox API for testing
```

### DigitalOcean

1. Create a token with **read/write** scope at https://cloud.digitalocean.com/account/api/tokens
2. Add to config:

```yaml
dns_providers:
  digitalocean_dns:
    type: digitalocean
    api_token: your-token
```

### Linode (Akamai)

1. Create a token with **Domains: Read/Write** scope at https://cloud.linode.com/profile/tokens
2. Add to config:

```yaml
dns_providers:
  linode_dns:
    type: linode
    api_token: your-token
```

### Namecheap

1. Enable API access at https://www.namecheap.com/support/api/intro/ and whitelist your IP
2. Add to config:

```yaml
dns_providers:
  namecheap_dns:
    type: namecheap
    api_key: your-api-key
    api_user: your-username
    client_ip: 1.2.3.4
```

---

## DNS Alias (Internal Hosts)

When a domain cannot have public DNS records (e.g. `server.internal.local`), use a DNS alias. The ACME challenge TXT record is published to the alias domain, and you create a CNAME from the original domain pointing to the alias:

```yaml
certificates:
  - name: internal-server
    domains:
      - server.internal.local
    dns_provider: cloudflare_dns
    dns_alias: _acme-challenge.acme.example.com
```

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
    dns_provider: cloudflare_dns
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
    dns_provider: cloudflare_dns
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
    dns_provider: cloudflare_dns
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
    dns_provider: cloudflare_dns
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
    dns_provider: cloudflare_dns
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
./cert_manager.rb verify                 # Test DNS provider credentials
./cert_manager.rb cleanup myserver       # Remove leftover ACME challenge DNS records
./cert_manager.rb revoke myserver        # Revoke a certificate
```

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
| dns_provider           | yes      | Provider name from `dns_providers`                                          |
| dns_alias              | no       | DNS alias domain for the ACME challenge TXT record                          |
| environment            | no       | Override default: `staging` or `production`                                 |
| reuse_key              | no       | Reuse the existing private key on renewal (defaults to `true`)              |
| deploy                 | no       | List of deploy targets (see Deployment Types above)                         |
