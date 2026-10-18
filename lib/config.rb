# frozen_string_literal: true

require 'yaml'
require_relative 'dns_providers'
require_relative 'file_permissions'
require_relative 'secret_store'

module CertManager
  class ConfigError < StandardError; end

  # Configuration loader and validator.
  #
  # Two file formats are supported:
  #   v2 (config.v2.yml, `version: 2`): providers own their zones and keep
  #      credentials (secrets encrypted with SecretStore); certificates are
  #      routed to a provider by the zones of their domains.
  #   v1 (config.yml, deprecated): flat `dns_providers` with plaintext
  #      credentials and an explicit `dns_provider` on every certificate.
  #
  # Either way, #dns_providers returns { name => { 'type' => ..., <flat, decrypted credentials> } }.
  class Config
    CONFIG_DIR = File.expand_path('~/.config/cert_manager')
    DEFAULT_CONFIG_PATH = File.join(CONFIG_DIR, 'config.v2.yml')
    LEGACY_CONFIG_PATH = File.join(CONFIG_DIR, 'config.yml')
    ENV_VAR = 'CERT_MANAGER_CONFIG'
    CURRENT_VERSION = 2
    ZONE_PATTERN = /\A(?:[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?\.)+[a-z0-9-]+\z/
    CHALLENGE_PREFIX = '_acme-challenge.'

    attr_reader :path, :version, :dns_providers, :certificates, :certbot_path,
                :config_dir, :work_dir, :logs_dir,
                :log_level, :propagation_wait, :email, :default_environment

    # Pick the config file to use: explicit path, $CERT_MANAGER_CONFIG, the v2
    # file, then the deprecated v1 file. Falls back to the v2 path when nothing exists.
    # @param explicit [String, nil] Path given with -c
    # @return [String]
    def self.resolve_path(explicit = nil)
      return File.expand_path(explicit) if explicit
      return File.expand_path(ENV[ENV_VAR]) if ENV[ENV_VAR] && !ENV[ENV_VAR].empty?
      return DEFAULT_CONFIG_PATH if File.exist?(DEFAULT_CONFIG_PATH)
      return LEGACY_CONFIG_PATH if File.exist?(LEGACY_CONFIG_PATH)

      DEFAULT_CONFIG_PATH
    end

      # Parse a configuration file into its top-level mapping (no validation)
      # @raise [ConfigError] if the file cannot be parsed or is not a mapping
      def self.read_document(path)
        doc = YAML.safe_load(File.read(path), permitted_classes: [Symbol])
        raise ConfigError, "Configuration file is empty or invalid: #{path}" unless doc.is_a?(Hash)

        doc
      rescue Psych::SyntaxError => e
        raise ConfigError, "Configuration file is not valid YAML: #{path} (#{e.message})"
      end

    # Where commands that create a v2 config (init, convert-config) should write:
    # explicit path, $CERT_MANAGER_CONFIG, then the default v2 path.
    def self.default_write_path(explicit = nil)
      return File.expand_path(explicit) if explicit
      return File.expand_path(ENV[ENV_VAR]) if ENV[ENV_VAR] && !ENV[ENV_VAR].empty?

      DEFAULT_CONFIG_PATH
    end

    # Hostnames whose zones decide which provider serves a certificate: the
    # dns_alias target when set (that is where challenges are placed), else the
    # certificate's domains without any wildcard prefix.
    # @param cert [Hash] Certificate configuration
    # @return [Array<String>]
    def self.routing_hosts(cert)
      if cert['dns_alias']
        [cert['dns_alias'].strip.downcase.chomp('.').delete_prefix(CHALLENGE_PREFIX)]
      else
        cert['domains'].map { |d| d.sub(/\A\*\./, '') }
      end
    end

    # Provider owning the longest zone that contains host
    # @param host [String]
    # @param zones_by_provider [Hash{String=>Array<String>}] normalized zones per provider
    # @return [String, nil] provider name, or nil when no zone matches
    def self.provider_for_host(host, zones_by_provider)
      host = host.downcase.chomp('.')
      best = zones_by_provider.flat_map { |name, zones| zones.map { |z| [z, name] } }
                              .select { |zone, _| host == zone || host.end_with?(".#{zone}") }
                              .max_by { |zone, _| zone.length }
      best&.last
    end

    # Normalize a zone name (case, trailing dot) and validate its shape
    # @return [String] normalized zone
    # @raise [ConfigError] if it is not a plausible DNS zone
    def self.normalize_zone(zone)
      normalized = zone.to_s.strip.downcase.chomp('.')
      unless ZONE_PATTERN.match?(normalized)
        raise ConfigError, "Invalid zone '#{zone}' (expected a domain like example.com)"
      end

      normalized
    end

    # Certificates are stored in config_dir/live
    def cert_dir
      File.join(@config_dir, 'live')
    end

    def legacy?
      @version < CURRENT_VERSION
    end

    # Path of the key file used for encrypted secrets
    def key_path
      SecretStore.key_path_for(@path)
    end

    # @param path [String, nil] Path to config file, resolved with Config.resolve_path
    # @param warnings [Boolean] Print the v1 deprecation and plaintext-secret notices (hook scripts disable them)
    def initialize(path = nil, warnings: true)
      @path = Config.resolve_path(path)
      @warnings = warnings
      load_config
    end

    # Zones configured for a provider (always empty for v1 configs)
    # @return [Array<String>]
    def zones(provider)
      zones_by_provider[provider] || []
    end

    # Name of the DNS provider that serves a certificate: its explicit
    # `dns_provider`, otherwise the provider owning the longest matching zone
    # for every domain (or for the dns_alias target, where challenges are placed).
    # @param cert [Hash] Certificate configuration
    # @return [String] provider name
    # @raise [ConfigError] if no provider, or more than one, matches
    def provider_name_for(cert)
      return cert['dns_provider'] if cert['dns_provider']

      hosts = Config.routing_hosts(cert)
      matches = hosts.to_h { |host| [host, provider_for_host(host)] }
      unresolved = matches.select { |_, name| name.nil? }.keys
      unless unresolved.empty?
        raise ConfigError, "No DNS provider has a zone for #{unresolved.join(', ')} " \
                           "(configured zones: #{all_zones.join(', ').then { |z| z.empty? ? 'none' : z }}). " \
                           "Add one with: add-zone PROVIDER ZONE"
      end

      names = matches.values.uniq
      if names.size > 1
        detail = matches.map { |host, name| "#{host} -> #{name}" }.join(', ')
        raise ConfigError, "Domains of one certificate must be served by a single provider (#{detail})"
      end

      names.first
    end

    private

    def zones_by_provider
      @zones_by_provider ||= {}
    end

    def all_zones
      zones_by_provider.values.flatten.sort
    end

    def provider_for_host(host)
      Config.provider_for_host(host, zones_by_provider)
    end

    # Load and parse the YAML configuration file
    # @raise [ConfigError] If the file is missing or invalid
    def load_config
      unless File.exist?(@path)
        raise ConfigError, "Configuration file not found: #{@path}\n" \
                           "Run `cert_manager.rb init` to create one, or `cert_manager.rb convert-config` " \
                           "to convert an existing v1 config."
      end

      FilePermissions.check(@path)

      config = Config.read_document(@path)

      @version = config.fetch('version', 1)
      unless [1, CURRENT_VERSION].include?(@version)
        raise ConfigError, "Unsupported config version #{@version.inspect} in #{@path} (supported: 1, #{CURRENT_VERSION})"
      end

      warn_deprecated if legacy? && @warnings

      @dns_providers = legacy? ? (config['dns_providers'] || {}) : load_v2_providers(config['providers'] || {})
      @certificates = config['certificates'] || []
      @certbot_path = config['certbot_path'] || 'certbot'

      # Certbot directory configuration (defaults to ~/.local/share/certbot)
      default_base = File.expand_path('~/.local/share/certbot')
      @config_dir = File.expand_path(config['config_dir'] || default_base)
      @work_dir = File.expand_path(config['work_dir'] || File.join(default_base, 'work'))
      @logs_dir = File.expand_path(config['logs_dir'] || File.join(default_base, 'logs'))

      @log_level = config['log_level'] || 'INFO'
      @propagation_wait = config['propagation_wait'] || 60
      @email = config['email']
      @default_environment = (config['environment'] || 'production').to_sym

      validate_config
    end

    def warn_deprecated
      warn "\e[1;33mDEPRECATED: #{@path} uses the old (v1) configuration format.\e[0m"
      warn "\e[1;33mConvert it (encrypts API keys, adds zones) with: cert_manager.rb convert-config\e[0m"
    end

    # Flatten v2 providers into the { name => { 'type' =>, credentials... } } shape
    # expected by DNSProviders.from_config, decrypting secrets.
    def load_v2_providers(providers)
      raise ConfigError, "'providers' must be a mapping of name to provider settings" unless providers.is_a?(Hash)

      store = nil
      providers.to_h do |name, settings|
        unless settings.is_a?(Hash)
          raise ConfigError, "DNS provider '#{name}' has no configuration (expected a mapping with 'type', 'credentials' and 'zones')"
        end
        raise ConfigError, "DNS provider '#{name}' is missing required 'type' field" unless settings['type']

        creds = settings['credentials'] || {}
        raise ConfigError, "DNS provider '#{name}': 'credentials' must be a mapping" unless creds.is_a?(Hash)

        secrets = DNSProviders.registered?(settings['type']) ? DNSProviders[settings['type']].secret_credentials : []
        plain = creds.to_h do |key, value|
          if SecretStore.encrypted?(value)
            store ||= open_secret_store
            [key, store.decrypt(value)]
          else
            warn "WARNING: #{name}.#{key} is stored in plaintext; run `update-provider-key #{name}` to encrypt it." if @warnings && secrets.include?(key.to_s)
            [key, value]
          end
        end

        zones_by_provider[name] = load_zones(name, settings['zones'])
        [name, { 'type' => settings['type'] }.merge(plain)]
      end
    end

    def open_secret_store
      SecretStore.new(key_path)
    rescue SecretStore::Error, SecurityError => e
      raise ConfigError, e.message
    end

    def load_zones(provider, zones)
      return [] if zones.nil?
      raise ConfigError, "DNS provider '#{provider}': 'zones' must be a list" unless zones.is_a?(Array)

      zones.map { |zone| Config.normalize_zone(zone) }
    end

    # Validate that configured certificates reference valid providers and domains
    # @raise [ConfigError] If validation fails
    def validate_config
      if @certificates.any? && @dns_providers.empty?
        raise ConfigError, "No DNS providers configured"
      end

      @dns_providers.each do |name, provider_config|
        unless provider_config.is_a?(Hash)
          raise ConfigError, "DNS provider '#{name}' has no configuration (expected a mapping with 'type' and credentials)"
        end
        unless provider_config['type']
          raise ConfigError, "DNS provider '#{name}' is missing required 'type' field"
        end
      end

      validate_unique_zones unless legacy?

      @certificates.each_with_index do |cert, i|
        unless cert.is_a?(Hash)
          raise ConfigError, "Certificate ##{i + 1} is not a valid mapping (got #{cert.inspect})"
        end

        cert_label = "Certificate ##{i + 1}#{" ('#{cert['name']}')" if cert['name']}"

        unless cert['domains'].is_a?(Array) && cert['domains'].any?
          raise ConfigError, "#{cert_label} is missing a 'domains' list"
        end

        cert['domains'].each_with_index do |domain, j|
          unless domain.is_a?(String) && !domain.strip.empty?
            raise ConfigError, "#{cert_label}: domain ##{j + 1} is not a valid string (got #{domain.inspect})"
          end
        end

        if cert['dns_alias'] && !(cert['dns_alias'].is_a?(String) && !cert['dns_alias'].strip.empty?)
          raise ConfigError, "#{cert_label}: 'dns_alias' must be a non-empty string"
        end

        provider = cert['dns_provider']
        if provider.nil? && legacy?
          raise ConfigError, "#{cert_label} is missing required 'dns_provider' field"
        elsif provider && !(provider.is_a?(String) && !provider.strip.empty?)
          raise ConfigError, "#{cert_label} is missing required 'dns_provider' field"
        elsif provider && !@dns_providers.key?(provider)
          raise ConfigError, "#{cert_label} references unknown dns_provider: '#{provider}' (configured: #{@dns_providers.keys.join(', ')})"
        end

        if cert['environment'] && !%w[staging production].include?(cert['environment'].to_s)
          raise ConfigError, "#{cert_label}: invalid environment '#{cert['environment']}' (must be 'staging' or 'production')"
        end

        begin
          provider_name_for(cert)
        rescue ConfigError => e
          raise ConfigError, "#{cert_label}: #{e.message}"
        end

        validate_deploy_config(cert['name'] || cert['domains'].first, cert['deploy']) if cert['deploy']
      end
    end

    # A zone may belong to only one provider
    def validate_unique_zones
      owners = {}
      zones_by_provider.each do |name, zones|
        zones.each do |zone|
          if owners.key?(zone) && owners[zone] != name
            raise ConfigError, "Zone '#{zone}' is configured on both '#{owners[zone]}' and '#{name}'"
          end
          owners[zone] = name
        end
      end
    end

    SUPPORTED_DEPLOY_SERVICES = %w[nginx apache copy].freeze
    SUPPORTED_DEPLOY_ACTIONS = %w[reload restart].freeze

    DEFAULT_SERVICE_NAMES = {
      'nginx' => 'nginx',
      'apache' => 'apache2'
    }.freeze

    # Validate deploy target configuration for a certificate
    # @param cert_name [String] Certificate name for error messages
    # @param deploy_targets [Array<Hash>] List of deploy target configurations
    # @raise [ConfigError] If any target is misconfigured
    def validate_deploy_config(cert_name, deploy_targets)
      unless deploy_targets.is_a?(Array)
        raise ConfigError, "Certificate '#{cert_name}': deploy must be a list of targets"
      end

      deploy_targets.each_with_index do |target, i|
        unless target.is_a?(Hash)
          raise ConfigError, "Certificate '#{cert_name}': deploy target ##{i + 1} is not a valid mapping (got #{target.inspect})"
        end

        tgt = "Certificate '#{cert_name}': deploy target ##{i + 1}"

        if target['local']
          %w[user host port].each do |field|
            if target.key?(field)
              raise ConfigError, "#{tgt}: '#{field}' is not valid for local deploy targets"
            end
          end

          %w[service path].each do |field|
            unless target[field].is_a?(String) && !target[field].strip.empty?
              raise ConfigError, "#{tgt} missing required field '#{field}'"
            end
          end
        else
          %w[user host service path].each do |field|
            unless target[field].is_a?(String) && !target[field].strip.empty?
              raise ConfigError, "#{tgt} missing required field '#{field}'"
            end
          end

          if target['port'] && !target['port'].is_a?(Integer)
            raise ConfigError, "#{tgt} 'port' must be an integer (got #{target['port'].inspect})"
          end
        end

        unless SUPPORTED_DEPLOY_SERVICES.include?(target['service'])
          raise ConfigError, "#{tgt} unsupported service '#{target['service']}' (supported: #{SUPPORTED_DEPLOY_SERVICES.join(', ')})"
        end

        unless target['path'].to_s.start_with?('/')
          raise ConfigError, "#{tgt} 'path' must be an absolute path (got '#{target['path']}')"
        end

        if target['key_path'] && !(target['key_path'].is_a?(String) && target['key_path'].start_with?('/'))
          raise ConfigError, "#{tgt} 'key_path' must be an absolute path (got '#{target['key_path']}')"
        end

        if target['action'] && !SUPPORTED_DEPLOY_ACTIONS.include?(target['action'])
          raise ConfigError, "#{tgt} unsupported action '#{target['action']}' (supported: #{SUPPORTED_DEPLOY_ACTIONS.join(', ')})"
        end

        if target.key?('sudo') && ![true, false].include?(target['sudo'])
          raise ConfigError, "#{tgt} 'sudo' must be true or false (got #{target['sudo'].inspect})"
        end

        if target.key?('append_key') && ![true, false].include?(target['append_key'])
          raise ConfigError, "#{tgt} 'append_key' must be true or false (got #{target['append_key'].inspect})"
        end

        if target['custom_command'] && target['service'] != 'copy'
          raise ConfigError, "#{tgt} custom_command is only supported with service 'copy'"
        end
      end
    end

  end
end
