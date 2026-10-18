# frozen_string_literal: true

require_relative 'config'

module CertManager
  # Converts a v1 configuration document into the v2 format: provider
  # credentials move under `credentials` with secrets passed through the
  # encryptor, zones are inferred from the certificates, and certificates keep
  # an explicit `dns_provider` only where zone routing would not reach the same
  # provider.
  class ConfigMigrator
    SETTINGS = %w[email certbot_path config_dir work_dir logs_dir log_level propagation_wait environment].freeze

    Result = Struct.new(:document, :encrypted, :zones, :explicit_certs, :warnings, keyword_init: true)

    # @param v1 [Hash] parsed v1 configuration
    # @param encryptor [#call] maps a plaintext secret to the value stored in the file
    def initialize(v1, encryptor:)
      @v1 = v1
      @encryptor = encryptor
    end

    # @return [Result]
    # @raise [ConfigError] if a certificate references a missing provider
    def migrate
      @warnings = []
      @encrypted = []
      providers = convert_providers
      zones = infer_zones(providers)
      providers.each { |name, settings| settings['zones'] = zones[name] }
      certificates, explicit = convert_certificates(zones)

      document = { 'version' => Config::CURRENT_VERSION }
      SETTINGS.each { |key| document[key] = @v1[key] if @v1.key?(key) }
      document['providers'] = providers
      document['certificates'] = certificates

      providers.each do |name, settings|
        @warnings << "Provider '#{name}' has no zones; add some with: add-zone #{name} ZONE" if settings['zones'].empty?
      end

      Result.new(document: document, encrypted: @encrypted, zones: zones, explicit_certs: explicit, warnings: @warnings)
    end

    private

    def v1_providers
      @v1['dns_providers'] || {}
    end

    def convert_providers
      v1_providers.to_h do |name, settings|
        raise ConfigError, "DNS provider '#{name}' has no configuration" unless settings.is_a?(Hash) && settings['type']

        type = settings['type']
        known = DNSProviders.registered?(type)
        secrets = known ? DNSProviders[type].secret_credentials : nil # nil: unknown type, treat every value as secret
        @warnings << "Provider '#{name}': unknown type '#{type}', all of its credentials were encrypted" unless known

        credentials = settings.reject { |key, _| key == 'type' }.to_h do |key, value|
          if (secrets.nil? || secrets.include?(key.to_s)) && !value.nil?
            @encrypted << "#{name}.#{key}"
            [key, @encryptor.call(value.to_s)]
          else
            [key, value]
          end
        end
        [name, { 'type' => type, 'credentials' => credentials, 'zones' => [] }]
      end
    end

    # Each root domain goes to the first provider whose certificates use it
    def infer_zones(providers)
      zones = providers.keys.to_h { |name| [name, []] }
      owners = {}
      each_cert do |cert, provider|
        Config.routing_hosts(cert).each do |host|
          root = DNSProviders::Base.root_domain(host.downcase)
          next if owners.key?(root)
          next unless usable_zone?(root)
          next if single_zone?(providers[provider]) && zones[provider].any?

          owners[root] = provider
          zones[provider] << root
        end
      end
      zones.transform_values(&:sort)
    end

    # Zones that fail validation (e.g. single-label names) stay unrouted; their certificates keep dns_provider
    def usable_zone?(root)
      Config.normalize_zone(root)
      true
    rescue ConfigError
      @warnings << "No valid zone can be inferred for '#{root}'; its certificate(s) keep an explicit dns_provider"
      false
    end

    # Providers pinned to one zone by an id credential can serve only the first zone found
    def single_zone?(settings)
      return false unless DNSProviders.registered?(settings['type'])

      key = DNSProviders[settings['type']].zone_credential
      !key.nil? && !settings['credentials'][key].to_s.empty?
    end

    def convert_certificates(zones)
      explicit = []
      certs = (@v1['certificates'] || []).map do |cert|
        converted = cert.dup
        provider = converted['dns_provider']
        routed = Config.routing_hosts(converted).map { |host| Config.provider_for_host(host, zones) }.uniq
        if routed == [provider]
          converted.delete('dns_provider')
        else
          explicit << (cert['name'] || cert['domains'].first)
        end
        converted
      end
      [certs, explicit]
    end

    def each_cert
      (@v1['certificates'] || []).each_with_index do |cert, i|
        label = "Certificate ##{i + 1}#{" ('#{cert['name']}')" if cert.is_a?(Hash) && cert['name']}"
        raise ConfigError, "#{label} is not a valid mapping" unless cert.is_a?(Hash)
        raise ConfigError, "#{label} is missing a 'domains' list" unless cert['domains'].is_a?(Array) && cert['domains'].any?

        provider = cert['dns_provider']
        unless v1_providers.key?(provider)
          raise ConfigError, "#{label} references unknown dns_provider '#{provider}'; fix the v1 config before converting"
        end

        yield cert, provider
      end
    end
  end
end
