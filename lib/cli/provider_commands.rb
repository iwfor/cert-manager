# frozen_string_literal: true

require_relative 'secret_input'

module CertManager
  module CLI
    # Commands that manage providers and zones in the v2 config file
    class ProviderCommands
      NAME_PATTERN = /\A[A-Za-z0-9][A-Za-z0-9_-]*\z/

      def initialize(options)
        @options = options
        @writer = ConfigWriter.new(Config.resolve_path(options[:config]))
      end

      def add_provider(name, type)
        raise UsageError, "Invalid provider name '#{name}' (use letters, digits, '-' and '_')" unless NAME_PATTERN.match?(name)
        raise "Provider '#{name}' already exists; use update-provider-key to change its key" if @writer.providers.key?(name)

        klass = provider_class(type)
        secrets = klass.secret_credentials
        settings = parse_settings(@options[:set])
        if (leaked = settings.keys & secrets).any?
          raise UsageError, "Secrets cannot be passed with --set (#{leaked.join(', ')}); use the prompt, --key-stdin or --key-env"
        end

        zones = (@options[:zone] || []).map { |z| Config.normalize_zone(z) }.uniq
        zones.each { |zone| ensure_zone_free(zone) }
        raise "#{type} providers serve a single zone; pass at most one --zone" if klass.zone_credential && zones.size > 1

        missing = klass.required_credentials - settings.keys
        input = SecretInput.new(@options, (missing & secrets).size)
        missing.each { |field| settings[field] = secrets.include?(field) ? input.read("#{field} for #{name}") : ask(field) }

        verify(name, type, settings, zones)
        if @options[:dry_run]
          return puts "Dry run: would add provider '#{name}' (#{type}) with zones: #{zones.empty? ? '(none)' : zones.join(', ')}"
        end

        store = @writer.secret_store
        @writer.providers[name] = { 'type' => type, 'credentials' => encrypt(settings, secrets, store), 'zones' => zones }
        save("Added provider '#{name}' (#{type})")
        puts "No zones yet; add one with: #{CLI.program} add-zone #{name} ZONE" if zones.empty?
      end

      def update_provider_key(name)
        provider = @writer.provider!(name)
        klass = provider_class(provider['type'])
        field = secret_field(klass, name)
        input = SecretInput.new(@options, 1)
        store = @writer.secret_store
        credentials = @writer.plain_credentials(name, store)
        credentials[field] = input.read("#{field} for #{name}")

        verify(name, provider['type'], credentials, @writer.zones_by_provider[name])
        return puts "Dry run: would update #{field} of provider '#{name}'" if @options[:dry_run]

        provider['credentials'] = (provider['credentials'] || {}).merge(field => store.encrypt(credentials[field]))
        save("Updated #{field} of provider '#{name}'")
      end

      def add_zone(name, zone)
        provider = @writer.provider!(name)
        klass = provider_class(provider['type'])
        zone = Config.normalize_zone(zone)
        ensure_zone_free(zone)

        credentials = provider['credentials'] ||= {}
        if (zone_id = @options[:zone_id])
          raise UsageError, "#{provider['type']} providers do not take --zone-id" unless klass.zone_credential

          credentials = credentials.merge(klass.zone_credential => zone_id)
        end
        if klass.zone_credential && credentials[klass.zone_credential] && (provider['zones'] || []).any?
          raise "Provider '#{name}' is tied to one zone (#{klass.zone_credential}); add another provider for #{zone}"
        end

        verify(name, provider['type'], verification_credentials(name, klass, credentials), [zone])
        return puts "Dry run: would add zone #{zone} to provider '#{name}'" if @options[:dry_run]

        provider['credentials'] = credentials
        provider['zones'] = ((provider['zones'] || []) + [zone]).sort
        save("Added zone #{zone} to provider '#{name}'")
      end

      def remove_zone(name, zone)
        provider = @writer.provider!(name)
        zone = Config.normalize_zone(zone)
        raise "Provider '#{name}' has no zone #{zone} (zones: #{(provider['zones'] || []).join(', ')})" unless @writer.zones_by_provider[name].include?(zone)

        after = @writer.zones_by_provider.merge(name => @writer.zones_by_provider[name] - [zone])
        guard_certificates(after, "zone #{zone}")
        return puts "Dry run: would remove zone #{zone} from provider '#{name}'" if @options[:dry_run]

        provider['zones'] = after[name]
        save("Removed zone #{zone} from provider '#{name}'")
      end

      def remove_provider(name)
        @writer.provider!(name)
        after = @writer.zones_by_provider.reject { |n, _| n == name }
        guard_certificates(after, "provider '#{name}'", removed: name)
        return puts "Dry run: would remove provider '#{name}'" if @options[:dry_run]
        unless Prompt.confirm("Remove provider '#{name}' and its stored credentials?", assume_yes: @options[:yes])
          raise 'Aborted; provider left in place'
        end

        @writer.providers.delete(name)
        save("Removed provider '#{name}'")
      end

      def list_providers
        if @writer.providers.empty?
          return puts "No providers configured. Add one with: #{CLI.program} add-provider NAME --type TYPE"
        end

        @writer.providers.each do |name, settings|
          klass = DNSProviders.registered?(settings['type']) ? DNSProviders[settings['type']] : nil
          secrets = klass ? klass.secret_credentials : []
          zones = settings['zones'] || []
          puts "#{name}  (#{settings['type']})"
          puts "  zones: #{zones.empty? ? '(none)' : zones.join(', ')}"
          (settings['credentials'] || {}).each do |key, value|
            puts "  #{key}: #{describe_credential(key, value, secrets)}"
          end
        end
      end

      private

      def provider_class(type)
        return DNSProviders[type] if DNSProviders.registered?(type.to_s)

        raise UsageError, "Unknown provider type '#{type}' (available: #{DNSProviders.available_types.join(', ')})"
      end

      def describe_credential(key, value, secrets)
        if SecretStore.encrypted?(value) then '[encrypted]'
        elsif secrets.include?(key.to_s) then '[PLAINTEXT - run update-provider-key to encrypt]'
        else value
        end
      end

      # Credentials for the verification call; skipped entirely (no key access) with --no-verify
      def verification_credentials(name, klass, pending)
        return {} if @options[:no_verify]

        @writer.plain_credentials(name, @writer.secret_store).merge(pending.slice(*klass.zone_credential))
      end

      def ask(field)
        value = Prompt.ask(field)
        raise "No value provided for #{field}" if value.empty?

        value
      end

      def parse_settings(pairs)
        (pairs || []).to_h do |pair|
          key, value = pair.split('=', 2)
          raise UsageError, "--set expects KEY=VALUE (got '#{pair}')" if value.nil? || key.empty?

          [key, value]
        end
      end

      def secret_field(klass, name)
        wanted = @options[:credential]
        secrets = klass.secret_credentials
        raise "Provider '#{name}' (#{klass.provider_type}) has no API key to update" if secrets.empty?
        if wanted
          return wanted if secrets.include?(wanted)

          raise UsageError, "'#{wanted}' is not a secret of #{klass.provider_type} (secrets: #{secrets.join(', ')})"
        end
        required = secrets & klass.required_credentials
        return required.first if required.size == 1 || (required.empty? && secrets.size == 1)

        raise UsageError, "Provider '#{name}' has several secrets (#{secrets.join(', ')}); choose one with --credential"
      end

      def encrypt(settings, secrets, store)
        settings.to_h { |key, value| [key, secrets.include?(key) ? store.encrypt(value) : value] }
      end

      def ensure_zone_free(zone)
        owner, = @writer.zones_by_provider.find { |_, zones| zones.include?(zone) }
        raise "Zone #{zone} is already served by provider '#{owner}'" if owner
      end

      # Ask the provider whether the credentials (and zones) work, unless --no-verify
      def verify(name, type, credentials, zones)
        return if @options[:no_verify]

        provider = DNSProviders.create(type, name, credentials)
        puts 'Verifying with the provider...' unless @options[:quiet]
        ok = provider.verify_credentials(zones)
        warn 'Note: nothing to check yet (no zones); credentials were not verified.' if !ok && !@options[:quiet]
      rescue ArgumentError, DNSProviders::DNSProviderError => e
        raise "Verification failed: #{e.message}\nNothing was saved. Re-run with --no-verify to save anyway."
      end

      # Refuse changes that would leave a certificate without its provider, unless --force
      def guard_certificates(zones_after, what, removed: nil)
        before = @writer.zones_by_provider
        broken = (@writer.data['certificates'] || []).filter_map do |cert|
          label = cert['name'] || cert['domains']&.first
          explicit = cert['dns_provider']
          if explicit
            label if explicit == removed
          else
            hosts = Config.routing_hosts(cert)
            was = hosts.map { |h| Config.provider_for_host(h, before) }
            label if was.uniq != hosts.map { |h| Config.provider_for_host(h, zones_after) }.uniq
          end
        end
        return if broken.empty? || @options[:force]

        raise "Removing #{what} would leave certificate(s) without a DNS provider: #{broken.join(', ')} (use --force to remove anyway)"
      end

      def save(message)
        backup = @writer.save
        puts "#{message}."
        puts "Previous version saved to #{backup}" if backup && @options[:verbose]
      end
    end

    common = %i[config dry_run quiet verbose]

    command 'add-provider', group: :configuration, summary: 'Add a DNS provider (encrypts its API key)',
            args: [arg('name', nil, desc: 'Your name for this provider, e.g. cloudflare-main')],
            options: [
              option(:type, long: '--type', arg: 'TYPE', desc: 'Provider type (see: help add-provider)', values: DNSProviders.available_types),
              option(:zone, long: '--zone', arg: 'ZONE', multiple: true, desc: 'Zone this provider serves (repeatable)'),
              option(:set, long: '--set', arg: 'KEY=VALUE', multiple: true, desc: 'Set a non-secret credential, e.g. region=us-east-1 (repeatable)'),
              option(:no_verify, long: '--no-verify', desc: 'Skip the check against the provider API'),
              *SecretInput::OPTIONS
            ],
            globals: common,
            description: "Types: #{DNSProviders.available_types.join(', ')}.\n" \
                         "Secrets are asked for with a hidden prompt (or --key-stdin / --key-env) and stored encrypted.\n" \
                         'Optional secrets (e.g. route53 secret_access_key) are added with update-provider-key --credential.',
            examples: ['add-provider cloudflare-main --type cloudflare --zone example.com',
                       'add-provider aws --type route53 --set hosted_zone_id=Z123 --zone example.org'] do |ctx|
      raise UsageError, '--type is required' unless ctx.options[:type]

      ProviderCommands.new(ctx.options).add_provider(ctx.args.first, ctx.options[:type])
    end

    command 'update-provider-key', group: :configuration, summary: "Replace a provider's API key",
            args: [arg('provider', :provider)],
            options: [
              option(:credential, long: '--credential', arg: 'FIELD', desc: 'Which secret to replace when a provider has several'),
              option(:no_verify, long: '--no-verify', desc: 'Skip the check against the provider API'),
              *SecretInput::OPTIONS
            ],
            globals: common,
            examples: ['update-provider-key cloudflare-main', 'update-provider-key dme --credential secret_key',
                       'update-provider-key cloudflare-main --key-env NEW_CF_TOKEN'] do |ctx|
      ProviderCommands.new(ctx.options).update_provider_key(ctx.args.first)
    end

    command 'add-zone', group: :configuration, summary: 'Let a provider serve a DNS zone',
            args: [arg('provider', :provider), arg('zone', nil, desc: 'e.g. example.com')],
            options: [
              option(:zone_id, long: '--zone-id', arg: 'ID', desc: 'Provider zone identifier (cloudflare zone_id, route53 hosted_zone_id, cloud_dns managed_zone)'),
              option(:no_verify, long: '--no-verify', desc: 'Skip the check against the provider API')
            ],
            globals: common,
            description: 'Certificates are routed to the provider whose zone is the longest match for their domains.',
            examples: ['add-zone cloudflare-main example.net'] do |ctx|
      ProviderCommands.new(ctx.options).add_zone(*ctx.args)
    end

    command 'remove-zone', group: :configuration, summary: 'Stop a provider serving a DNS zone',
            args: [arg('provider', :provider), arg('zone', :zone)],
            globals: common + [:force],
            description: 'Refuses if a certificate would be left without a provider, unless --force.' do |ctx|
      ProviderCommands.new(ctx.options).remove_zone(*ctx.args)
    end

    command 'remove-provider', group: :configuration, summary: 'Remove a DNS provider and its stored credentials',
            args: [arg('provider', :provider)],
            globals: common + %i[force yes],
            description: 'Refuses if a certificate would be left without a provider, unless --force.' do |ctx|
      ProviderCommands.new(ctx.options).remove_provider(ctx.args.first)
    end

    command 'list-providers', group: :configuration, summary: 'List providers, their zones and credential status',
            globals: %i[config],
            description: 'Secrets are never printed.' do |ctx|
      ProviderCommands.new(ctx.options).list_providers
    end
  end
end
