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
    * DigitalOcean, Linode, Namecheap
* Support DNS aliases in requests
* Support both staging and production certificates
    * Encourage user to create a staging certificate before switching to production

## Command line and config (v2)

* Config is `config.v2.yml` (`version: 2`) with `providers` (type, `credentials`, `zones`) and `certificates`;
  certificates are routed to a provider by longest matching zone (`dns_provider` is an optional override)
* The legacy `config.yml` (v1) still loads but prints a deprecation notice; `convert-config` migrates it
* Secrets are stored as `ENC[v1:...]` (AES-256-GCM) using `cert-manager.key` beside the config (0600, enforced).
  Secret fields are declared per provider with `secret_credentials`; never accept secrets on the command line
* Providers/zones are managed by commands (`add-provider`, `update-provider-key`, `add-zone`, `remove-zone`, ...),
  which edit the file through `ConfigWriter` (atomic, 0600, timestamped `.bak`)
* All commands and flags are defined in the CLI registry (`lib/cli.rb`, `lib/cli/*.rb`). Help text and the bash/zsh
  completions are generated from it, so **a new command or option must be added through the registry, with an `Arg` kind
  (`:certificate`, `:provider`, `:zone`, ...) where its value can be completed**. `test/completions_test.rb` fails if
  a command or flag is missing from the generated scripts
* Run the tests with `rake test` (or `ruby -Itest -e 'Dir["test/*_test.rb"].each { |f| require "./#{f}" }'`)

## Project Tree

```
├── cert_manager.rb              # Entry point + Manager (cert lifecycle, deploy logic)
├── config.v2.yml.example        # Sample v2 configuration file
├── test_dns_provider.rb         # DNS provider test script
├── lib/
│   ├── cli.rb                   # Command registry, option parsing, help
│   ├── cli/
│   │   ├── commands.rb          # Certificate + setup commands (init, convert-config, help)
│   │   ├── provider_commands.rb # add-provider, update-provider-key, add/remove-zone, ...
│   │   ├── completion_commands.rb # completions, hidden __complete callback
│   │   ├── convert_config.rb    # convert-config implementation
│   │   ├── secret_input.rb      # Hidden prompt / --key-stdin / --key-env
│   │   └── prompt.rb            # EOF-safe prompts
│   ├── completions.rb           # bash/zsh script generation + dynamic candidates
│   ├── config.rb                # Config loader/validator (v1 + v2), zone routing
│   ├── config_writer.rb         # Atomic rewrites of the v2 file
│   ├── config_migrator.rb       # v1 -> v2 conversion
│   ├── secret_store.rb          # Key file + AES-256-GCM value encryption
│   ├── file_permissions.rb      # Permission checks (warn / require private)
│   ├── dns_providers.rb         # Provider loader and factory
│   └── dns_providers/
│       ├── base.rb              # Base class (secret_credentials, zone_credential, verify_credentials)
│       ├── cloudflare.rb        # Cloudflare DNS API
│       ├── dreamhost.rb         # Dreamhost DNS API
│       ├── route53.rb           # AWS Route 53
│       ├── cloud_dns.rb         # Google Cloud DNS
│       ├── dnsmadeeasy.rb       # DNS Made Easy
│       ├── digitalocean.rb      # DigitalOcean
│       ├── linode.rb            # Linode (Akamai)
│       └── namecheap.rb         # Namecheap
└── test/                        # Test::Unit tests (rake test)
```
