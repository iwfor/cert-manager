Let's Encrypt Cert Manager
==========================

* Use the Let's Encrypt `certbot` tool to request and renew certificates
* The user should be able to run the tool directly to request new certificates
* The tool should be easy to integrate into a daily cron job to run renewals
* DNS based authorization for `certbot`, supporting:
    * Cloudflare DNS API
    * Dreamhost DNS API
    * Google CloudDNS
    * AWS Route 53
    * DNS Made Easy
* Support DNS aliases in requests
* Support both staging and production certificates
    * Encourage user to create a staging certificate before switching to production

## Project Tree

```
├── cert_manager.rb              # Main script: CLI, config, cert lifecycle, deploy logic
├── config.yml.example           # Sample configuration file
├── test_dns_provider.rb         # DNS provider test script
├── lib/
│   ├── dns_providers.rb         # Provider loader and factory
│   └── dns_providers/
│       ├── base.rb              # Base class for all DNS providers
│       ├── cloudflare.rb        # Cloudflare DNS API
│       ├── dreamhost.rb         # Dreamhost DNS API
│       ├── route53.rb           # AWS Route 53
│       ├── cloud_dns.rb         # Google Cloud DNS
│       └── dnsmadeeasy.rb       # DNS Made Easy
└── live/                        # Certbot data directory (gitignored)
    ├── accounts/                # ACME account registrations
    ├── archive/                 # Certificate archive
    ├── live/                    # Current certificate symlinks
    └── renewal/                 # Renewal configuration
```
