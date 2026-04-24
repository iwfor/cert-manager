#!/usr/bin/env ruby
# frozen_string_literal: true

# Let's Encrypt Certificate Manager for Internal Hosts
# Supports DNS-based authorization via pluggable DNS providers

require 'yaml'
require 'json'
require 'fileutils'
require 'optparse'
require 'logger'
require 'time'
require 'openssl'
require 'digest'

require_relative 'lib/dns_providers'
require_relative 'lib/file_permissions'

module CertManager
  VERSION = '1.0.0'

  # ACME server URLs
  ACME_SERVERS = {
    production: 'https://acme-v02.api.letsencrypt.org/directory',
    staging: 'https://acme-staging-v02.api.letsencrypt.org/directory'
  }.freeze

  # Configuration loader and validator
  class Config
    DEFAULT_CONFIG_PATH = File.expand_path('~/.config/cert_manager/config.yml')

    attr_reader :dns_providers, :certificates, :certbot_path,
                :config_dir, :work_dir, :logs_dir,
                :log_level, :propagation_wait, :email, :default_environment

    # Certificates are stored in config_dir/live
    def cert_dir
      File.join(@config_dir, 'live')
    end

    # @param path [String, nil] Path to config file, defaults to DEFAULT_CONFIG_PATH
    def initialize(path = nil)
      @path = path || DEFAULT_CONFIG_PATH
      load_config
    end

    private

    # Load and parse the YAML configuration file
    # @raise [ConfigError] If the file is missing or invalid
    def load_config
      unless File.exist?(@path)
        raise ConfigError, "Configuration file not found: #{@path}\n" \
                           "Run with --init to create a sample configuration."
      end

      FilePermissions.check(@path)

      config = YAML.safe_load(File.read(@path), permitted_classes: [Symbol])

      unless config.is_a?(Hash)
        raise ConfigError, "Configuration file is empty or invalid: #{@path}"
      end

      @dns_providers = config['dns_providers'] || {}
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

        provider = cert['dns_provider']
        unless provider.is_a?(String) && !provider.strip.empty?
          raise ConfigError, "#{cert_label} is missing required 'dns_provider' field"
        end
        unless @dns_providers.key?(provider)
          raise ConfigError, "#{cert_label} references unknown dns_provider: '#{provider}' (configured: #{@dns_providers.keys.join(', ')})"
        end

        if cert['environment'] && !%w[staging production].include?(cert['environment'].to_s)
          raise ConfigError, "#{cert_label}: invalid environment '#{cert['environment']}' (must be 'staging' or 'production')"
        end

        if cert['dns_alias'] && !(cert['dns_alias'].is_a?(String) && !cert['dns_alias'].strip.empty?)
          raise ConfigError, "#{cert_label}: 'dns_alias' must be a non-empty string"
        end

        validate_deploy_config(cert['name'] || cert['domains'].first, cert['deploy']) if cert['deploy']
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

  class ConfigError < StandardError; end

  # Main certificate manager
  class Manager
    attr_reader :environment

    # @param config_path [String, nil] Path to config file
    # @param dry_run [Boolean] If true, show what would be done without making changes
    # @param environment [Symbol, nil] Environment override (:staging or :production)
    # @param quiet [Boolean] If true, suppress info-level log output
    # @param skip_prompts [Boolean] If true, skip interactive confirmation prompts
    # @param verbose [Boolean] If true, show extra detail such as certbot commands
    def initialize(config_path: nil, dry_run: false, environment: nil, quiet: false, skip_prompts: false, verbose: false)
      @config = Config.new(config_path)
      @dry_run = dry_run
      @environment_override = environment
      @quiet = quiet
      @skip_prompts = skip_prompts
      @verbose = verbose
      @logger = setup_logger
      @providers = DNSProviders.from_config(@config.dns_providers)
    end

    # Determine the effective environment for a certificate
    def effective_environment(cert_config)
      # CLI override takes precedence
      return @environment_override if @environment_override

      # Certificate-level setting (legacy 'staging' bool or new 'environment')
      if cert_config['environment']
        cert_config['environment'].to_sym
      elsif cert_config['staging']
        :staging
      else
        @config.default_environment
      end
    end

    # Request a new certificate
    def request(cert_name)
      cert_config = find_certificate(cert_name)
      raise "Certificate '#{cert_name}' not found in configuration" unless cert_config

      request_certificate(cert_config)
    end

    # Deploy a certificate to its configured targets
    # @param cert_name [String] Certificate name or primary domain
    # @param force [Boolean] If true, clear any recorded failure state before deploying
    def deploy(cert_name, force: false)
      cert_config = find_certificate(cert_name)
      raise "Certificate '#{cert_name}' not found in configuration" unless cert_config

      unless cert_config['deploy']&.any?
        raise "Certificate '#{cert_name}' has no deploy targets configured"
      end

      actual_name = cert_name_for(cert_config)
      active_name = resolve_active_cert_name(actual_name)
      cert_path = File.join(@config.cert_dir, active_name, 'cert.pem')
      unless File.exist?(cert_path) || @dry_run
        raise "Certificate files not found for '#{cert_name}' — request or renew first"
      end

      if force
        clear_all_pending_deploys(actual_name)
        @logger.info("Cleared recorded failure state for '#{actual_name}'")
      end

      deploy_certificate(cert_config)
    end

    # Retry any previously failed deploys from the state file
    def retry_failed_deploys
      state = load_deploy_state
      pending = state['pending_deploys']
      return if pending.empty?

      @logger.info("Found #{pending.length} pending deploy(s) to retry")

      succeeded = 0
      failed = 0

      pending.dup.each do |entry|
        cert_name = entry['cert_name']
        target = entry['target']
        host = target['host']

        dest = target['local'] ? 'localhost' : "#{target['user']}@#{host}"

        if @dry_run
          @logger.info("[DRY RUN] Would retry deploy of '#{cert_name}' to #{dest}")
          next
        end

        @logger.info("Retrying deploy of '#{cert_name}' to #{dest}")

        begin
          deploy_single_target(cert_name, target)
          clear_pending_deploy(cert_name, target)
          @logger.info("Retry succeeded for #{cert_name} -> #{host}")
          succeeded += 1
        rescue StandardError => e
          @logger.warn("Retry failed for #{cert_name} -> #{host}: #{e.message}")
          record_failed_deploy(cert_name, target, e.message)
          failed += 1
        end
      end

      @logger.info("Deploy retries complete: #{succeeded} succeeded, #{failed} failed")
    end

    # Renew certificates that are due
    # If cert_name is provided, only renew that certificate
    # If cert_name is nil, renew all certificates due for renewal
    def renew(cert_name: nil, force: false)
      retry_failed_deploys

      renewed = 0

      certificates_to_check = if cert_name
        cert_config = find_certificate(cert_name)
        raise "Certificate '#{cert_name}' not found in configuration" unless cert_config
        [cert_config]
      else
        @config.certificates
      end

      certificates_to_check.each do |cert_config|
        name = cert_name_for(cert_config)

        if force || certificate_needs_renewal?(cert_config)
          @logger.info("Renewing certificate: #{name}")
          request_certificate(cert_config)
          renewed += 1
        else
          @logger.info("Certificate #{name} does not need renewal")
        end
      end

      @logger.info("Renewed #{renewed} certificate(s)")
      renewed
    end

    # Print the current environment setting (override or default)
    def print_environment_info
      if @environment_override
        puts "Environment override: #{@environment_override.to_s.upcase}"
      else
        puts "Default environment: #{@config.default_environment.to_s.upcase}"
      end
      puts ""
    end

    # List all certificates and their status
    def list
      puts "Configured Certificates:"
      puts "-" * 60

      @config.certificates.each do |cert_config|
        print_certificate_status(cert_config)
      end
    end

    # Verify DNS provider credentials
    def verify_providers
      @config.dns_providers.each do |name, _|
        provider = @providers[name]
        print "Verifying #{name} (#{provider.class.provider_type})... "

        begin
          # Try a simple operation to verify credentials
          case provider
          when DNSProviders::Cloudflare
            # List zones to verify token
            provider.send(:get_zone_id, 'example.com')
          when DNSProviders::Dreamhost
            provider.list_records
          end
          puts "OK"
        rescue StandardError => e
          puts "FAILED: #{e.message}"
        end
      end
    end

    # Clean up leftover ACME challenge records for a certificate
    def cleanup(cert_name)
      cert_config = find_certificate(cert_name)
      raise "Certificate '#{cert_name}' not found in configuration" unless cert_config

      domains = cert_config['domains']
      provider_name = cert_config['dns_provider']
      provider = @providers[provider_name]

      raise "Unknown DNS provider: #{provider_name}" unless provider

      @logger.info("Cleaning up ACME challenge records for: #{domains.join(', ')}")

      domains.each do |domain|
        record_name = cert_config['dns_alias'] || "_acme-challenge.#{domain}"
        @logger.info("Looking for TXT records: #{record_name}")

        begin
          count = provider.cleanup_challenge_records(domain)
          @logger.info("Removed #{count} record(s) for #{domain}")
        rescue StandardError => e
          @logger.warn("Failed to cleanup #{domain}: #{e.message}")
        end
      end

      @logger.info("Cleanup complete")
    end

    # Revoke a certificate
    def revoke(cert_name, reason: nil)
      cert_config = find_certificate(cert_name)
      raise "Certificate '#{cert_name}' not found in configuration" unless cert_config

      actual_name = cert_name_for(cert_config)
      cert_path = File.join(@config.cert_dir, actual_name, 'cert.pem')

      unless File.exist?(cert_path)
        raise "Certificate file not found: #{cert_path}"
      end

      @logger.info("Revoking certificate: #{actual_name}")

      unless @skip_prompts
        puts ""
        puts "WARNING: You are about to revoke the certificate for:"
        puts "  #{cert_config['domains'].join(', ')}"
        puts ""
        puts "This action cannot be undone. The certificate will be"
        puts "invalidated immediately and must be re-issued."
        puts ""
        print "Are you sure you want to revoke? [y/N] "

        unless $stdin.gets&.strip&.downcase == 'y'
          puts "Aborted."
          return
        end
      end

      if @dry_run
        @logger.info("[DRY RUN] Would revoke certificate: #{actual_name}")
        return
      end

      env = effective_environment(cert_config)
      run_certbot_revoke(cert_path, reason, env)
      @logger.info("Certificate revoked successfully")
    end

    private

    # Run certbot revoke for a certificate
    # @param cert_path [String] Path to the certificate PEM file
    # @param reason [String, nil] Revocation reason (e.g. 'keycompromise', 'superseded')
    # @param environment [Symbol] :staging or :production
    def run_certbot_revoke(cert_path, reason, environment)
      cmd = [
        @config.certbot_path,
        'revoke',
        '--cert-path', cert_path,
        '--config-dir', @config.config_dir,
        '--work-dir', @config.work_dir,
        '--logs-dir', @config.logs_dir,
        '--agree-tos',
        '--non-interactive'
      ]

      # Add reason if specified
      # Valid reasons: unspecified, keycompromise, affiliationchanged,
      #                superseded, cessationofoperation
      if reason
        cmd += ['--reason', reason]
      end

      # Set ACME server based on environment
      if environment == :staging
        cmd += ['--server', ACME_SERVERS[:staging]]
      else
        cmd += ['--server', ACME_SERVERS[:production]]
      end

      # Echo command in verbose mode
      if @verbose
        puts "Certbot command:"
        puts "  #{cmd.join(' ')}"
        puts ""
      end

      unless system(*cmd)
        raise "Certbot revoke command failed with exit code: #{$?.exitstatus}"
      end
    end

    # Initialize the logger with level based on config and quiet mode
    # @return [Logger]
    def setup_logger
      logger = Logger.new($stdout)
      # In quiet mode, only show warnings and errors
      if @quiet
        logger.level = Logger::WARN
      else
        logger.level = Logger.const_get(@config.log_level.upcase)
      end
      logger.formatter = proc do |severity, datetime, _progname, msg|
        "[#{datetime.strftime('%Y-%m-%d %H:%M:%S')}] #{severity}: #{msg}\n"
      end
      logger
    end

    # Return the display name for a certificate config
    # @param cert_config [Hash] Certificate configuration hash
    # @return [String] The cert name or first domain
    def cert_name_for(cert_config)
      cert_config['name'] || cert_config['domains'].first
    end

    # Find the cert directory that actually holds the newest certificate.
    # Certbot may create suffixed directories (e.g. eng-0006) when it can't
    # renew in place; this returns whichever name (the configured one, or a
    # "<name>-NNNN" sibling) has the cert.pem with the latest expiry.
    # Memoized per-instance so the warning only logs once per cert.
    def resolve_active_cert_name(cert_name)
      @resolved_cert_names ||= {}
      return @resolved_cert_names[cert_name] if @resolved_cert_names.key?(cert_name)

      prefix = "#{cert_name}-"
      suffixed = if Dir.exist?(@config.cert_dir)
                   Dir.entries(@config.cert_dir).select do |entry|
                     entry.start_with?(prefix) &&
                       entry[prefix.length..] =~ /\A\d+\z/ &&
                       File.directory?(File.join(@config.cert_dir, entry))
                   end
                 else
                   []
                 end

      candidates = [cert_name] + suffixed
      with_expiry = candidates.filter_map do |name|
        cert_path = File.join(@config.cert_dir, name, 'cert.pem')
        next unless File.exist?(cert_path)
        expiry = get_certificate_expiry(cert_path)
        [name, expiry] if expiry
      end

      newest_name = with_expiry.empty? ? cert_name : with_expiry.max_by { |_, e| e }.first

      if newest_name != cert_name
        @logger.warn("Active cert for '#{cert_name}' is in '#{newest_name}/' — " \
                     "certbot created a suffixed directory instead of renewing in place.")
        @logger.warn("Consolidate with: certbot rename --cert-name #{newest_name} " \
                     "--new-name #{cert_name} --config-dir #{@config.config_dir}")
      end

      @resolved_cert_names[cert_name] = newest_name
    end

    # Calculate fractional days remaining until an expiry time
    # @param expiry [Time] Certificate expiry time
    # @return [Float] Days until expiry (negative if expired)
    def days_until_expiry(expiry)
      (expiry - Time.now) / 86400
    end

    # Return the shared Ruby code preamble used by certbot hook scripts
    # to load config and instantiate the DNS provider
    # @return [String] Ruby source code fragment
    def hook_script_preamble
      <<~'RUBY'
        config = YAML.safe_load(File.read(ENV["CERT_MANAGER_CONFIG"]))
        provider_config = config["dns_providers"][ENV["CERT_MANAGER_PROVIDER"]]
        provider = CertManager::DNSProviders.create(
          provider_config["type"],
          ENV["CERT_MANAGER_PROVIDER"],
          provider_config.reject { |k, _| k == "type" }
        )
      RUBY
    end

    # Look up a certificate config by name or primary domain
    # @param name [String] Certificate name or domain to find
    # @return [Hash, nil] The matching certificate config, or nil
    def find_certificate(name)
      @config.certificates.find do |c|
        c['name'] == name || c['domains'].first == name
      end
    end

    # Request a new certificate via certbot, with staging prompt and deploy
    # @param cert_config [Hash] Certificate configuration hash
    def request_certificate(cert_config)
      domains = cert_config['domains']
      provider_name = cert_config['dns_provider']
      dns_alias = cert_config['dns_alias']
      env = effective_environment(cert_config)
      cert_name = cert_name_for(cert_config)

      # Encourage staging for first-time production requests
      if env == :production && !certificate_exists?(cert_config)
        unless @skip_prompts
          puts ""
          puts "=" * 60
          puts "RECOMMENDATION: Test with staging first!"
          puts "=" * 60
          puts ""
          puts "This appears to be a new certificate. Before requesting a"
          puts "production certificate, we recommend testing with staging:"
          puts ""
          puts "  #{$PROGRAM_NAME} --staging request #{cert_name}"
          puts ""
          puts "Staging certificates are not trusted by browsers but verify"
          puts "that your DNS configuration is correct without using up your"
          puts "Let's Encrypt rate limits (5 failures per hour for production)."
          puts ""
          print "Continue with production certificate? [y/N] "

          unless $stdin.gets&.strip&.downcase == 'y'
            puts "Aborted. Use --staging to request a test certificate first."
            return
          end
        end
      end

      env_label = env == :staging ? '[STAGING]' : '[PRODUCTION]'
      @logger.info("#{env_label} Requesting certificate for: #{domains.join(', ')}")

      provider = @providers[provider_name]
      raise "Unknown DNS provider: #{provider_name}" unless provider

      if @dry_run
        @logger.info("[DRY RUN] Would request #{env} certificate for #{domains.join(', ')}")
        deploy_certificate(cert_config) if cert_config['deploy']&.any?
        return
      end

      # Use certbot with manual hooks
      run_certbot_with_hooks(domains, provider, dns_alias, cert_config, env)
    end

    # Check whether a certificate PEM file exists on disk
    # @param cert_config [Hash] Certificate configuration hash
    # @return [Boolean]
    def certificate_exists?(cert_config)
      cert_name = cert_name_for(cert_config)
      cert_path = File.join(@config.cert_dir, cert_name, 'cert.pem')
      File.exist?(cert_path)
    end

    # Build and execute the certbot certonly command with DNS auth/cleanup hooks
    # @param domains [Array<String>] Domains to include in the certificate
    # @param provider [CertManager::DNSProviders::Base] DNS provider instance
    # @param dns_alias [String, nil] Optional DNS alias for ACME challenge records
    # @param cert_config [Hash] Certificate configuration hash
    # @param environment [Symbol] :staging or :production
    def run_certbot_with_hooks(domains, provider, dns_alias, cert_config, environment)
      # Ensure directories exist
      ensure_directories_exist

      # Build domain arguments
      domain_args = domains.flat_map { |d| ['-d', d] }

      # Build certbot command
      cmd = [
        @config.certbot_path,
        'certonly',
        '--manual',
        '--preferred-challenges', 'dns',
        '--manual-auth-hook', auth_hook_script(provider, dns_alias),
        '--manual-cleanup-hook', cleanup_hook_script(provider, dns_alias),
        '--config-dir', @config.config_dir,
        '--work-dir', @config.work_dir,
        '--logs-dir', @config.logs_dir,
        '--agree-tos',
        '--non-interactive'
      ]

      cmd += ['--email', @config.email] if @config.email
      cmd += ['--cert-name', cert_name_for(cert_config)]
      cmd += domain_args

      # Reuse existing private key by default; opt out with reuse_key: false
      cmd << '--reuse-key' if cert_config.fetch('reuse_key', true)

      # Set ACME server based on environment
      if environment == :staging
        cmd += ['--server', ACME_SERVERS[:staging]]
      else
        cmd += ['--server', ACME_SERVERS[:production]]
      end

      # Echo command in verbose mode
      if @verbose
        puts "Certbot command:"
        puts "  #{cmd.join(' ')}"
        puts ""
      end

      # Set environment for hooks
      env = {
        'CERT_MANAGER_PROVIDER' => provider.name,
        'CERT_MANAGER_CONFIG' => @config.instance_variable_get(:@path),
        'CERT_MANAGER_PROPAGATION_WAIT' => @config.propagation_wait.to_s
      }
      env['CERT_MANAGER_DNS_ALIAS'] = dns_alias if dns_alias

      # Record the cert serial before certbot runs so we can detect if it changed
      cert_name = cert_name_for(cert_config)
      cert_path = File.join(@config.cert_dir, cert_name, 'fullchain.pem')
      old_serial = begin
        OpenSSL::X509::Certificate.new(File.read(File.realpath(cert_path))).serial
      rescue StandardError
        nil
      end

      success = system(env, *cmd)

      unless success
        raise "Certbot command failed with exit code: #{$?.exitstatus}"
      end

      # Verify certbot actually updated the cert at the expected path.
      # Certbot silently creates a new cert name (e.g. eng-0001) when it hits a
      # naming conflict, leaving the old cert at the original path untouched.
      begin
        new_serial = OpenSSL::X509::Certificate.new(File.read(File.realpath(cert_path))).serial
        if old_serial && new_serial == old_serial
          # Cert at expected path didn't change — certbot likely renamed it
          suffixed = Dir[File.join(@config.cert_dir, "#{cert_name}-*")]
            .select { |d| File.directory?(d) }
            .sort
          hint = if suffixed.any?
                   latest = File.basename(suffixed.last)
                   "Found '#{latest}' which may be the renewed cert. " \
                   "Run: certbot rename --cert-name #{latest} --new-name #{cert_name} " \
                   "--config-dir #{@config.config_dir}"
                 else
                   "Check: certbot certificates --config-dir #{@config.config_dir}"
                 end
          raise "Certbot succeeded but the certificate at #{cert_path} was not updated. " \
                "Certbot may have created a duplicate cert with a suffixed name. #{hint}"
        end
      rescue Errno::ENOENT
        raise "Certbot succeeded but no certificate found at #{cert_path}. " \
              "Check: certbot certificates --config-dir #{@config.config_dir}"
      end

      deploy_certificate(cert_config) if cert_config['deploy']&.any?

      @logger.info("Certificate obtained successfully!")
    end

    # Generate the certbot manual auth hook script that adds DNS TXT records
    # @param provider [CertManager::DNSProviders::Base] DNS provider instance
    # @param dns_alias [String, nil] Optional DNS alias for challenge records
    # @return [String] Path to the generated temporary script
    def auth_hook_script(provider, dns_alias)
      lib_path = File.expand_path('lib/dns_providers', __dir__)
      preamble = hook_script_preamble

      script = <<~RUBY
        #!/usr/bin/env ruby
        require 'yaml'
        require '#{lib_path}'

        begin
        #{preamble}
          domain = ENV["CERTBOT_DOMAIN"]
          validation = ENV["CERTBOT_VALIDATION"]
          record_name = ENV["CERT_MANAGER_DNS_ALIAS"] || "_acme-challenge.\#{domain}"

          puts "Adding TXT record: \#{record_name} = \#{validation}"
          record_id = provider.add_txt_record(domain, record_name, validation)

          # Store record ID for cleanup
          File.write("/tmp/certbot_record_\#{domain}", record_id.to_s)
          puts "Record ID saved: \#{record_id}"

          # Wait for propagation
          puts "Waiting \#{ENV["CERT_MANAGER_PROPAGATION_WAIT"]}s for DNS propagation..."
          sleep(ENV["CERT_MANAGER_PROPAGATION_WAIT"].to_i)
        rescue => e
          STDERR.puts "Auth hook error: \#{e.message}"
          STDERR.puts e.backtrace.first(5).join("\\n")
          exit 1
        end
      RUBY

      write_temp_script('auth_hook.rb', script)
    end

    # Generate the certbot manual cleanup hook script that removes DNS TXT records
    # @param provider [CertManager::DNSProviders::Base] DNS provider instance
    # @param dns_alias [String, nil] Optional DNS alias for challenge records
    # @return [String] Path to the generated temporary script
    def cleanup_hook_script(provider, dns_alias)
      lib_path = File.expand_path('lib/dns_providers', __dir__)
      preamble = hook_script_preamble

      script = <<~RUBY
        #!/usr/bin/env ruby
        require 'yaml'
        require '#{lib_path}'

        begin
        #{preamble}
          domain = ENV["CERTBOT_DOMAIN"]
          validation = ENV["CERTBOT_VALIDATION"]

          record_id_file = "/tmp/certbot_record_\#{domain}"
          if File.exist?(record_id_file)
            record_id = File.read(record_id_file).strip
            puts "Removing TXT record: \#{record_id} for \#{domain}"
            provider.remove_txt_record(domain, record_id, validation)
            File.delete(record_id_file)
            puts "TXT record removed successfully"
          else
            STDERR.puts "Warning: Record ID file not found: \#{record_id_file}"
          end
        rescue => e
          STDERR.puts "Cleanup hook error: \#{e.message}"
          STDERR.puts e.backtrace.first(5).join("\\n")
          exit 1
        end
      RUBY

      write_temp_script('cleanup_hook.rb', script)
    end

    # Write a temporary executable script file
    # @param name [String] Base name for the script
    # @param content [String] Script content
    # @return [String] Path to the created script
    def write_temp_script(name, content)
      path = "/tmp/cert_manager_#{name}_#{$$}"
      File.write(path, content)
      File.chmod(0o755, path)
      path
    end

    # Create certbot config, work, and log directories if they don't exist
    def ensure_directories_exist
      [@config.config_dir, @config.work_dir, @config.logs_dir].each do |dir|
        FileUtils.mkdir_p(dir) unless File.exist?(dir)
      end
    end

    # Resolve the systemctl unit name for a deploy target.
    # Returns nil for 'copy' (no service restart needed).
    def resolve_service_unit(target)
      return nil if target['service'] == 'copy'

      target['service_name'] || Config::DEFAULT_SERVICE_NAMES[target['service']] || target['service']
    end

    # Deploy a certificate to all configured targets, logging dry-run info or
    # recording failures for later retry
    # @param cert_config [Hash] Certificate configuration hash
    def deploy_certificate(cert_config)
      cert_name = cert_name_for(cert_config)

      cert_config['deploy'].each do |target|
        sudo = target.fetch('sudo', true) != false ? 'sudo ' : ''
        action = target['action'] || 'reload'
        unit = resolve_service_unit(target)

        if @dry_run
          if target['local']
            @logger.info("[DRY RUN] Would deploy locally")
            @logger.info("[DRY RUN]   #{sudo}cp fullchain.pem #{target['path']}")
            if target['append_key']
              @logger.info("[DRY RUN]   #{sudo}cat privkey.pem >> #{target['path']}")
              @logger.info("[DRY RUN]   #{sudo}chmod 0600 #{target['path']}")
            end
            if target['key_path']
              @logger.info("[DRY RUN]   #{sudo}cp privkey.pem #{target['key_path']}")
              @logger.info("[DRY RUN]   #{sudo}chmod 0600 #{target['key_path']}")
            end
            @logger.info("[DRY RUN]   #{sudo}systemctl #{action} #{unit}") if unit
            @logger.info("[DRY RUN]   #{target['custom_command']}") if target['custom_command']
          else
            remote = "#{target['user']}@#{target['host']}"
            @logger.info("[DRY RUN] Would deploy to #{remote}")
            @logger.info("[DRY RUN]   scp fullchain.pem -> #{remote}:/tmp/")
            @logger.info("[DRY RUN]   #{sudo}cp /tmp/fullchain.pem #{target['path']}")
            if target['append_key']
              @logger.info("[DRY RUN]   scp privkey.pem -> #{remote}:/tmp/")
              @logger.info("[DRY RUN]   #{sudo}cat /tmp/privkey.pem >> #{target['path']}")
              @logger.info("[DRY RUN]   #{sudo}chmod 0600 #{target['path']}")
            end
            if target['key_path']
              @logger.info("[DRY RUN]   scp privkey.pem -> #{remote}:/tmp/")
              @logger.info("[DRY RUN]   #{sudo}cp /tmp/privkey.pem #{target['key_path']}")
              @logger.info("[DRY RUN]   #{sudo}chmod 0600 #{target['key_path']}")
            end
            @logger.info("[DRY RUN]   #{sudo}systemctl #{action} #{unit}") if unit
            @logger.info("[DRY RUN]   ssh #{remote} #{target['custom_command']}") if target['custom_command']
          end
          next
        end

        dest = target['local'] ? 'localhost' : "#{target['user']}@#{target['host']}"
        begin
          deploy_single_target(cert_name, target)
          clear_pending_deploy(cert_name, target)
          @logger.info("Successfully deployed to #{dest}")
        rescue StandardError => e
          @logger.warn("Deploy failed for #{cert_name} -> #{dest}: #{e.message}")
          record_failed_deploy(cert_name, target, e.message)
        end
      end
    end

    # Deploy certificate files to a single target (local or remote)
    # @param cert_name [String] Certificate name (used to locate cert files)
    # @param target [Hash] Deploy target configuration
    # @return [Boolean] true on success
    def deploy_single_target(cert_name, target)
      active_name = resolve_active_cert_name(cert_name)
      cert_dir = File.join(@config.cert_dir, active_name)
      warn_if_stale_live_symlink(cert_dir, active_name)
      path = target['path']
      key_path = target['key_path']
      append_key = target['append_key']
      custom_command = target['custom_command']
      unit = resolve_service_unit(target)
      action = target['action'] || 'reload'
      sudo = target.fetch('sudo', true) != false ? 'sudo ' : ''

      if target['local']
        deploy_local(cert_dir, path, key_path, append_key, unit, action, sudo, custom_command)
      else
        deploy_remote(cert_dir, target, path, key_path, append_key, unit, action, sudo, custom_command)
      end

      true
    end

    # Deploy certificate files locally via cp and optional systemctl reload/restart
    # @param cert_dir [String] Directory containing cert PEM files
    # @param path [String] Destination path for the fullchain certificate
    # @param key_path [String, nil] Optional separate destination for the private key
    # @param append_key [Boolean, nil] If true, append private key to the cert file
    # @param unit [String, nil] Systemctl unit name to reload/restart
    # @param action [String] 'reload' or 'restart'
    # @param sudo [String] 'sudo ' prefix or empty string
    # @param custom_command [String, nil] Optional post-deploy command to run
    def deploy_local(cert_dir, path, key_path, append_key, unit, action, sudo, custom_command)
      @logger.info("Deploying certificate locally to #{path}")
      run_deploy_cmd(
        ['sh', '-c', "#{sudo}cp #{File.join(cert_dir, 'fullchain.pem')} #{path}"],
        "Failed to install certificate to #{path}"
      )

      if append_key
        @logger.info("Appending private key to #{path}")
        run_deploy_cmd(
          ['sh', '-c', "#{sudo}cat #{File.join(cert_dir, 'privkey.pem')} >> #{path} && #{sudo}chmod 0600 #{path}"],
          "Failed to append private key to #{path}"
        )
      end

      if key_path
        @logger.info("Deploying private key locally to #{key_path}")
        run_deploy_cmd(
          ['sh', '-c', "#{sudo}cp #{File.join(cert_dir, 'privkey.pem')} #{key_path} && #{sudo}chmod 0600 #{key_path}"],
          "Failed to install private key to #{key_path}"
        )
      end

      if unit
        @logger.info("Running: #{sudo}systemctl #{action} #{unit}")
        run_deploy_cmd(
          ['sh', '-c', "#{sudo}systemctl #{action} #{unit}"],
          "Failed to #{action} #{unit}"
        )
      end

      if custom_command
        @logger.info("Running custom command: #{custom_command}")
        run_deploy_cmd(
          ['sh', '-c', custom_command],
          "Custom command failed"
        )
      end
    end

    # Deploy certificate files to a remote host via scp/ssh
    # @param cert_dir [String] Directory containing cert PEM files
    # @param target [Hash] Deploy target config (must include 'user' and 'host')
    # @param path [String] Remote destination path for the fullchain certificate
    # @param key_path [String, nil] Optional separate remote destination for the private key
    # @param append_key [Boolean, nil] If true, append private key to the cert file
    # @param unit [String, nil] Systemctl unit name to reload/restart on remote
    # @param action [String] 'reload' or 'restart'
    # @param sudo [String] 'sudo ' prefix or empty string
    # @param custom_command [String, nil] Optional post-deploy command to run on remote
    def deploy_remote(cert_dir, target, path, key_path, append_key, unit, action, sudo, custom_command)
      user = target['user']
      host = target['host']
      remote = "#{user}@#{host}"

      ssh_opts = %w[-o StrictHostKeyChecking=accept-new -o BatchMode=yes]

      # Resolve symlink so we deploy the actual archive file, not a dangling reference
      cert_file = File.realpath(File.join(cert_dir, 'fullchain.pem'))
      local_cert = OpenSSL::X509::Certificate.new(File.read(cert_file))
      serial_hex = local_cert.serial.to_s(16).upcase
      local_hash = Digest::SHA256.file(cert_file).hexdigest
      @logger.info("Deploying #{cert_file} to #{remote}:#{path} " \
                   "(serial=#{serial_hex}, expires=#{local_cert.not_after.strftime('%Y-%m-%d')}, " \
                   "sha256=#{local_hash[0..15]})")

      # Upload cert to temp, then install into place.
      # Uses 'install' instead of 'cp': install unlinks the destination first,
      # so it replaces symlinks with a new regular file rather than writing
      # through them to a potentially stale target.
      tmp_cert = "/tmp/cert_manager_fullchain_#{$$}.pem"
      scp_cert = ['scp', *ssh_opts, cert_file, "#{remote}:#{tmp_cert}"]
      install_cert = ['ssh', *ssh_opts, remote,
                      "#{sudo}install -m 0644 #{tmp_cert} #{path} && rm -f #{tmp_cert}"]

      run_deploy_cmd(scp_cert, "Failed to upload certificate to #{remote}")
      run_deploy_cmd(install_cert, "Failed to install certificate to #{path} on #{host}")

      # Verify the installed file content matches what we deployed
      verify_remote_file(remote, path, local_hash, ssh_opts, sudo, host)

      # Append private key to cert file if configured
      if append_key
        tmp_key = "/tmp/cert_manager_privkey_#{$$}.pem"
        scp_key = ['scp', *ssh_opts,
                   File.join(cert_dir, 'privkey.pem'),
                   "#{remote}:#{tmp_key}"]
        append_cmd = ['ssh', *ssh_opts, remote,
                      "#{sudo}cat #{tmp_key} >> #{path} && #{sudo}chmod 0600 #{path} && rm -f #{tmp_key}"]

        @logger.info("Appending private key to #{remote}:#{path}")
        run_deploy_cmd(scp_key, "Failed to upload private key to #{remote}")
        run_deploy_cmd(append_cmd, "Failed to append private key to #{path} on #{host}")
      end

      # Upload private key if key_path is configured
      if key_path
        tmp_key = "/tmp/cert_manager_privkey_#{$$}.pem"
        scp_key = ['scp', *ssh_opts,
                   File.join(cert_dir, 'privkey.pem'),
                   "#{remote}:#{tmp_key}"]
        install_key = ['ssh', *ssh_opts, remote,
                       "#{sudo}cp #{tmp_key} #{key_path} && #{sudo}chmod 0600 #{key_path} && rm -f #{tmp_key}"]

        @logger.info("Deploying private key to #{remote}:#{key_path}")
        run_deploy_cmd(scp_key, "Failed to upload private key to #{remote}")
        run_deploy_cmd(install_key, "Failed to install private key to #{key_path} on #{host}")
      end

      # Reload/restart the service
      if unit
        service_cmd = ['ssh', *ssh_opts, remote, "#{sudo}systemctl #{action} #{unit}"]
        @logger.info("Running: #{sudo}systemctl #{action} #{unit}")
        run_deploy_cmd(service_cmd, "Failed to #{action} #{unit} on #{host}")
      end

      # Run custom command if configured
      if custom_command
        @logger.info("Running custom command on #{remote}: #{custom_command}")
        run_deploy_cmd(
          ['ssh', *ssh_opts, remote, custom_command],
          "Custom command failed on #{host}"
        )
      end
    end

    # Warn if the live symlink points to a stale cert or to a non-standard archive location.
    # Catches two cases:
    #   1. A newer numbered archive file exists alongside the one the symlink points to.
    #   2. The symlink resolves into a non-standard location (e.g. inside live/ instead of
    #      next to it), while a standard certbot archive exists at the expected path.
    # @param cert_dir [String] Path to the live cert directory (e.g. live/example.com)
    # @param cert_name [String] Certificate name for log messages
    def warn_if_stale_live_symlink(cert_dir, cert_name)
      live_link = File.join(cert_dir, 'fullchain.pem')
      return unless File.symlink?(live_link)

      real = File.realpath(live_link)
      archive_dir = File.dirname(real)
      base = File.basename(real)             # e.g. fullchain3.pem
      prefix = base.sub(/\d+\.pem$/, '')    # e.g. "fullchain"
      current_num = base[/(\d+)\.pem$/, 1]&.to_i
      return unless current_num

      # Check for a newer archive file in the same directory the symlink resolves to
      newest_same = Dir[File.join(archive_dir, "#{prefix}*.pem")]
        .map { |f| File.basename(f)[/(\d+)\.pem$/, 1]&.to_i }
        .compact.max

      if newest_same && newest_same > current_num
        @logger.warn("Live symlink for '#{cert_name}' points to #{base} but " \
                     "#{prefix}#{newest_same}.pem exists in the same archive — " \
                     "the symlink may not have been updated after renewal.")
      end

      # Check whether the symlink resolves into the standard certbot archive location.
      # cert_dir is live/CERT_NAME; two levels up is the certbot config_dir.
      standard_archive = File.join(File.dirname(File.dirname(cert_dir)), 'archive', cert_name)
      return unless Dir.exist?(standard_archive)
      return if real.start_with?(File.expand_path(standard_archive) + File::SEPARATOR)

      # The live symlink doesn't point into the standard archive — warn and show what's there
      newest_standard = Dir[File.join(standard_archive, "#{prefix}*.pem")]
        .map { |f| File.basename(f)[/(\d+)\.pem$/, 1]&.to_i }
        .compact.max

      if newest_standard
        @logger.warn("Live symlink for '#{cert_name}' resolves to #{real}")
        @logger.warn("  but the standard certbot archive has #{prefix}#{newest_standard}.pem at #{standard_archive}/")
        @logger.warn("  The cert was likely renewed into the standard archive but the live symlink was not updated.")
        @logger.warn("  Fix with:")
        @logger.warn("    cd #{cert_dir}")
        %w[cert chain fullchain privkey].each do |name|
          src = File.join(standard_archive, "#{name}#{newest_standard}.pem")
          @logger.warn("    ln -sf ../../archive/#{cert_name}/#{name}#{newest_standard}.pem #{name}.pem") if File.exist?(src)
        end
      end
    end

    # Verify that the file installed on a remote host has the expected content by
    # comparing SHA-256 hashes. Raises on mismatch so the deploy is recorded as failed.
    # @param remote [String] "user@host"
    # @param path [String] Remote file path to verify
    # @param expected_hash [String] Hex SHA-256 hash of the local source file
    # @param ssh_opts [Array<String>] SSH options
    # @param sudo [String] 'sudo ' or ''
    # @param host [String] Hostname for error messages
    def verify_remote_file(remote, path, expected_hash, ssh_opts, sudo, host)
      cmd = ['ssh', *ssh_opts, remote, "#{sudo}sha256sum #{path}"]
      output = IO.popen(cmd, &:read)
      unless $?.success?
        raise "Could not verify installed file on #{host}: sha256sum failed (exit #{$?.exitstatus})"
      end

      remote_hash = output.strip.split(/\s+/).first&.downcase

      unless remote_hash == expected_hash
        raise "Certificate content verification failed on #{host}: " \
              "installed file hash #{remote_hash} does not match local hash #{expected_hash}. " \
              "The file at #{path} was not updated — check whether the path is a symlink or " \
              "a config management tool is overwriting it."
      end

      @logger.info("Certificate content verified on #{host} (sha256=#{remote_hash[0..15]})")
    end

    # Execute a deploy command, raising on failure
    # @param cmd [Array<String>] Command and arguments
    # @param error_message [String] Error message prefix if command fails
    # @raise [RuntimeError] If the command exits with a non-zero status
    def run_deploy_cmd(cmd, error_message)
      puts "Deploy command: #{cmd.join(' ')}" if @verbose
      unless system(*cmd)
        raise "#{error_message} (exit code: #{$?.exitstatus})"
      end
    end

    # Path to the JSON file tracking pending/failed deploys
    # @return [String]
    def deploy_state_path
      File.join(@config.config_dir, 'deploy_state.json')
    end

    # Load the deploy state from disk, returning a default if missing or corrupt
    # @return [Hash] State hash with 'pending_deploys' key
    def load_deploy_state
      return { 'pending_deploys' => [] } unless File.exist?(deploy_state_path)

      data = File.read(deploy_state_path).strip
      return { 'pending_deploys' => [] } if data.empty?

      JSON.parse(data)
    rescue JSON::ParserError
      { 'pending_deploys' => [] }
    end

    # Persist the deploy state hash to disk as pretty-printed JSON
    # @param state [Hash] State hash to save
    def save_deploy_state(state)
      File.write(deploy_state_path, JSON.pretty_generate(state))
    end

    # Return a unique host identifier for a deploy target ('localhost' or hostname)
    # @param target [Hash] Deploy target configuration
    # @return [String]
    def deploy_host_key(target)
      target['local'] ? 'localhost' : target['host']
    end

    # Record a failed deploy in the state file for later retry
    # @param cert_name [String] Certificate name
    # @param target [Hash] Deploy target configuration
    # @param error_message [String] Error description
    def record_failed_deploy(cert_name, target, error_message)
      state = load_deploy_state
      pending = state['pending_deploys']

      # Update existing entry or add new one, keyed by cert_name + host
      host_key = deploy_host_key(target)
      existing = pending.find { |e| e['cert_name'] == cert_name && deploy_host_key(e['target']) == host_key }
      if existing
        existing['failed_at'] = Time.now.utc.iso8601
        existing['last_error'] = error_message
      else
        pending << {
          'cert_name' => cert_name,
          'target' => target,
          'failed_at' => Time.now.utc.iso8601,
          'last_error' => error_message
        }
      end

      save_deploy_state(state)
    end

    # Remove a successfully completed deploy from the pending state
    # @param cert_name [String] Certificate name
    # @param target [Hash] Deploy target configuration
    def clear_pending_deploy(cert_name, target)
      state = load_deploy_state
      host_key = deploy_host_key(target)
      state['pending_deploys'].reject! { |e| e['cert_name'] == cert_name && deploy_host_key(e['target']) == host_key }
      save_deploy_state(state)
    end

    # Remove all recorded failures for a certificate (used by force deploy)
    # @param cert_name [String] Certificate name
    def clear_all_pending_deploys(cert_name)
      state = load_deploy_state
      state['pending_deploys'].reject! { |e| e['cert_name'] == cert_name }
      save_deploy_state(state)
    end

    # Check if a certificate needs renewal (missing, unreadable, or expiring soon)
    # @param cert_config [Hash] Certificate configuration hash
    # @param days_threshold [Integer] Renew if fewer than this many days remain
    # @return [Boolean]
    def certificate_needs_renewal?(cert_config, days_threshold: 30)
      cert_name = cert_name_for(cert_config)
      cert_path = File.join(@config.cert_dir, cert_name, 'cert.pem')

      return true unless File.exist?(cert_path)

      expiry = get_certificate_expiry(cert_path)
      return true unless expiry

      days_remaining = days_until_expiry(expiry)
      days_remaining < days_threshold
    end

    # Parse the expiry date from a PEM certificate using openssl
    # @param cert_path [String] Path to the certificate PEM file
    # @return [Time, nil] Expiry time, or nil if unreadable
    def get_certificate_expiry(cert_path)
      output = `openssl x509 -enddate -noout -in "#{cert_path}" 2>/dev/null`
      return nil unless $?.success?

      if output =~ /notAfter=(.+)/
        Time.parse($1)
      end
    rescue ArgumentError
      nil
    end

    # Print detailed status for a single certificate (domains, expiry, deploy targets)
    # @param cert_config [Hash] Certificate configuration hash
    def print_certificate_status(cert_config)
      cert_name = cert_name_for(cert_config)
      cert_path = File.join(@config.cert_dir, cert_name, 'cert.pem')
      env = effective_environment(cert_config)

      puts "\n#{cert_name}:"
      puts "  Domains: #{cert_config['domains'].join(', ')}"
      puts "  DNS Provider: #{cert_config['dns_provider']}"
      puts "  DNS Alias: #{cert_config['dns_alias'] || 'none'}"
      puts "  Environment: #{env.to_s.upcase}"

      if File.exist?(cert_path)
        expiry = get_certificate_expiry(cert_path)
        if expiry
          days_left = days_until_expiry(expiry).to_i
          status = days_left < 30 ? 'NEEDS RENEWAL' : 'OK'
          puts "  Expires: #{expiry.strftime('%Y-%m-%d')} (#{days_left} days)"
          puts "  Status: #{status}"
        else
          puts "  Status: UNABLE TO READ CERTIFICATE"
        end
      else
        puts "  Status: NOT ISSUED"
      end

      if cert_config['deploy']&.any?
        state = load_deploy_state
        pending = state['pending_deploys'].select { |e| e['cert_name'] == cert_name }

        puts "  Deploy targets:"
        cert_config['deploy'].each do |target|
          key_info = target['key_path'] ? " + key:#{target['key_path']}" : ""
          key_info += " [combined]" if target['append_key']
          dest = target['local'] ? "localhost" : "#{target['user']}@#{target['host']}"
          unit = resolve_service_unit(target)
          service_info = if unit
                           action = target['action'] || 'reload'
                           "#{action} #{unit}"
                         else
                           "copy only"
                         end
          line = "    - #{dest}:#{target['path']}#{key_info} (#{service_info})"

          failed = pending.find { |e| deploy_host_key(e['target']) == deploy_host_key(target) }
          if failed
            line += " DEPLOY FAILED"
            puts line
            puts "      Last failure: #{failed['failed_at']}"
            puts "      Error: #{failed['last_error']}"
          else
            puts line
          end
        end
      end
    end

  end

  # Generate sample configuration
  def self.generate_sample_config(path)
    config = <<~YAML
      # CertManager Configuration
      # See documentation for full options

      # Email for Let's Encrypt notifications
      email: admin@example.com

      # Path to certbot binary (optional, defaults to 'certbot')
      certbot_path: certbot

      # Certbot directory configuration (all default to ~/.local/share/certbot)
      # config_dir: ~/.local/share/certbot
      # work_dir: ~/.local/share/certbot/work
      # logs_dir: ~/.local/share/certbot/logs

      # Log level: DEBUG, INFO, WARN, ERROR (optional, defaults to INFO)
      log_level: INFO

      # Seconds to wait for DNS propagation (optional, defaults to 60)
      propagation_wait: 60

      # Default environment: 'production' or 'staging' (optional, defaults to 'production')
      # Can be overridden per-certificate or via CLI flags (--staging / --production)
      environment: production

      # DNS Providers
      # Configure one or more DNS providers with their credentials
      dns_providers:
        # Cloudflare example
        cloudflare_main:
          type: cloudflare
          api_token: your-cloudflare-api-token
          # Optional: specify zone_id to skip zone lookup
          # zone_id: abc123

        # Dreamhost example
        dreamhost_backup:
          type: dreamhost
          api_key: your-dreamhost-api-key

        # AWS Route 53 example (requires: gem install aws-sdk-route53)
        # route53_main:
        #   type: route53
        #   hosted_zone_id: Z1234567890ABC
        #   access_key_id: AKIAIOSFODNN7EXAMPLE      # optional, uses AWS credential chain
        #   secret_access_key: your-secret-key       # optional

        # GCP Cloud DNS example (requires: gem install google-apis-dns_v1 googleauth)
        # gcp_dns:
        #   type: cloud_dns
        #   project_id: my-project-123
        #   managed_zone: my-zone-name
        #   credentials_file: /path/to/service-account.json  # optional, uses ADC

        # DNS Made Easy example
        # dnsmadeeasy_dns:
        #   type: dnsmadeeasy
        #   api_key: your-api-key
        #   secret_key: your-secret-key

      # Certificates to manage
      certificates:
        # Production certificate with deployment to target hosts
        - name: internal-server
          domains:
            - internal.example.com
          dns_provider: cloudflare_main
          # Deploy cert files to remote hosts via SSH after obtaining/renewing
          # deploy:
          #   - user: deploy
          #     host: web1.example.com
          #     path: /etc/ssl/certs/example.com
          #     service: nginx
          #     action: reload    # reload (default) or restart

        # Wildcard certificate
        - name: wildcard-internal
          domains:
            - "*.internal.example.com"
            - internal.example.com
          dns_provider: cloudflare_main

        # Certificate with DNS alias (for internal hosts)
        # The ACME challenge will be placed at the alias domain instead
        - name: private-server
          domains:
            - private.internal.local
          dns_provider: cloudflare_main
          dns_alias: _acme-challenge.acme.example.com

        # Staging certificate for testing
        - name: test-cert
          domains:
            - test.example.com
          dns_provider: dreamhost_backup
          environment: staging
    YAML

    dir = File.dirname(path)
    FileUtils.mkdir_p(dir) unless File.exist?(dir)
    File.write(path, config)
    puts "Sample configuration written to: #{path}"
  end
end

# CLI interface
if __FILE__ == $PROGRAM_NAME
  options = {
    config: nil,
    dry_run: false,
    force: false,
    environment: nil,
    quiet: false,
    yes: false,
    verbose: false
  }

  parser = OptionParser.new do |opts|
    opts.banner = "Usage: #{$PROGRAM_NAME} [options] <command> [args]"
    opts.separator ""
    opts.separator "Commands:"
    opts.separator "  request <name>    Request a new certificate"
    opts.separator "  deploy <name>     Deploy certificate to configured targets (use -f to clear failure state)"
    opts.separator "  renew [name]      Renew certificate(s) due for renewal"
    opts.separator "  revoke <name>     Revoke a certificate"
    opts.separator "  cleanup <name>    Remove leftover ACME challenge DNS records"
    opts.separator "  list              List all configured certificates"
    opts.separator "  verify            Verify DNS provider credentials"
    opts.separator "  init              Create sample configuration file"
    opts.separator ""
    opts.separator "Options:"

    opts.on('-c', '--config PATH', 'Path to configuration file') do |path|
      options[:config] = path
    end

    opts.on('-n', '--dry-run', 'Show what would be done without making changes') do
      options[:dry_run] = true
    end

    opts.on('-f', '--force', 'Force renewal even if not due; with deploy, clears recorded failure state') do
      options[:force] = true
    end

    opts.on('-s', '--staging', 'Use Let\'s Encrypt staging environment (test certificates)') do
      options[:environment] = :staging
    end

    opts.on('-p', '--production', 'Use Let\'s Encrypt production environment (real certificates)') do
      options[:environment] = :production
    end

    opts.on('-q', '--quiet', 'Quiet mode for cron jobs (only output errors)') do
      options[:quiet] = true
    end

    opts.on('-y', '--yes', 'Skip confirmation prompts (for automation)') do
      options[:yes] = true
    end

    opts.on('-r', '--reason REASON', 'Revocation reason (keycompromise, superseded, etc.)') do |reason|
      options[:reason] = reason
    end

    opts.on('-v', '--verbose', 'Enable verbose output') do
      options[:verbose] = true
    end

    opts.on('-V', '--version', 'Show version') do
      puts "CertManager v#{CertManager::VERSION}"
      exit
    end

    opts.on('-h', '--help', 'Show this help') do
      puts opts
      exit
    end
  end

  parser.parse!

  command = ARGV.shift

  case command
  when 'init'
    config_path = options[:config] || CertManager::Config::DEFAULT_CONFIG_PATH
    if File.exist?(config_path)
      print "Configuration file already exists. Overwrite? [y/N] "
      exit unless $stdin.gets.strip.downcase == 'y'
    end
    CertManager.generate_sample_config(config_path)

  when 'request'
    cert_name = ARGV.shift
    unless cert_name
      puts "Error: Certificate name required"
      puts "Usage: #{$PROGRAM_NAME} request <cert_name>"
      exit 1
    end

    begin
      manager = CertManager::Manager.new(
        config_path: options[:config],
        dry_run: options[:dry_run],
        environment: options[:environment],
        quiet: options[:quiet],
        skip_prompts: options[:yes],
        verbose: options[:verbose]
      )
      manager.request(cert_name)
    rescue StandardError => e
      puts "Error: #{e.message}"
      exit 1
    end

  when 'deploy'
    cert_name = ARGV.shift
    unless cert_name
      puts "Error: Certificate name required"
      puts "Usage: #{$PROGRAM_NAME} deploy <cert_name>"
      exit 1
    end

    begin
      manager = CertManager::Manager.new(
        config_path: options[:config],
        dry_run: options[:dry_run],
        quiet: options[:quiet],
        skip_prompts: options[:yes],
        verbose: options[:verbose]
      )
      manager.deploy(cert_name, force: options[:force])
    rescue StandardError => e
      puts "Error: #{e.message}"
      exit 1
    end

  when 'renew'
    cert_name = ARGV.shift  # Optional certificate name

    begin
      manager = CertManager::Manager.new(
        config_path: options[:config],
        dry_run: options[:dry_run],
        environment: options[:environment],
        quiet: options[:quiet],
        skip_prompts: options[:yes],
        verbose: options[:verbose]
      )
      manager.renew(cert_name: cert_name, force: options[:force])
    rescue StandardError => e
      puts "Error: #{e.message}"
      exit 1
    end

  when 'revoke'
    cert_name = ARGV.shift
    unless cert_name
      puts "Error: Certificate name required"
      puts "Usage: #{$PROGRAM_NAME} revoke <cert_name>"
      exit 1
    end

    begin
      manager = CertManager::Manager.new(
        config_path: options[:config],
        dry_run: options[:dry_run],
        environment: options[:environment],
        quiet: options[:quiet],
        skip_prompts: options[:yes],
        verbose: options[:verbose]
      )
      manager.revoke(cert_name, reason: options[:reason])
    rescue StandardError => e
      puts "Error: #{e.message}"
      exit 1
    end

  when 'cleanup'
    cert_name = ARGV.shift
    unless cert_name
      puts "Error: Certificate name required"
      puts "Usage: #{$PROGRAM_NAME} cleanup <cert_name>"
      exit 1
    end

    begin
      manager = CertManager::Manager.new(
        config_path: options[:config],
        quiet: options[:quiet],
        verbose: options[:verbose]
      )
      manager.cleanup(cert_name)
    rescue StandardError => e
      puts "Error: #{e.message}"
      exit 1
    end

  when 'list'
    begin
      manager = CertManager::Manager.new(
        config_path: options[:config],
        environment: options[:environment],
        verbose: options[:verbose]
      )
      manager.print_environment_info
      manager.list
    rescue StandardError => e
      puts "Error: #{e.message}"
      exit 1
    end

  when 'verify'
    begin
      manager = CertManager::Manager.new(
        config_path: options[:config],
        verbose: options[:verbose]
      )
      manager.verify_providers
    rescue StandardError => e
      puts "Error: #{e.message}"
      exit 1
    end

  else
    puts parser
    exit 1
  end
end
