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

require_relative 'lib/dns_providers'

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

    attr_reader :dns_providers, :certificates, :certbot_path, :cert_dir,
                :log_level, :propagation_wait, :email, :default_environment

    def initialize(path = nil)
      @path = path || DEFAULT_CONFIG_PATH
      load_config
    end

    private

    def load_config
      unless File.exist?(@path)
        raise ConfigError, "Configuration file not found: #{@path}\n" \
                           "Run with --init to create a sample configuration."
      end

      config = YAML.safe_load(File.read(@path), permitted_classes: [Symbol])

      @dns_providers = config['dns_providers'] || {}
      @certificates = config['certificates'] || []
      @certbot_path = config['certbot_path'] || 'certbot'
      @cert_dir = config['cert_dir'] || '/etc/letsencrypt/live'
      @log_level = config['log_level'] || 'INFO'
      @propagation_wait = config['propagation_wait'] || 60
      @email = config['email']
      @default_environment = (config['environment'] || 'production').to_sym

      validate_config
    end

    def validate_config
      if @certificates.any? && @dns_providers.empty?
        raise ConfigError, "No DNS providers configured"
      end

      @certificates.each do |cert|
        unless cert['domains']&.any?
          raise ConfigError, "Certificate missing 'domains' field"
        end

        provider = cert['dns_provider']
        unless @dns_providers.key?(provider)
          raise ConfigError, "Certificate references unknown provider: #{provider}"
        end
      end
    end
  end

  class ConfigError < StandardError; end

  # Main certificate manager
  class Manager
    attr_reader :environment

    def initialize(config_path: nil, dry_run: false, environment: nil, quiet: false, skip_prompts: false)
      @config = Config.new(config_path)
      @dry_run = dry_run
      @environment_override = environment
      @quiet = quiet
      @skip_prompts = skip_prompts
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

    # Renew certificates that are due
    def renew(force: false)
      renewed = 0

      @config.certificates.each do |cert_config|
        cert_name = cert_config['name'] || cert_config['domains'].first

        if force || certificate_needs_renewal?(cert_config)
          @logger.info("Renewing certificate: #{cert_name}")
          request_certificate(cert_config)
          renewed += 1
        else
          @logger.info("Certificate #{cert_name} does not need renewal")
        end
      end

      @logger.info("Renewed #{renewed} certificate(s)")
      renewed
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

    private

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

    def find_certificate(name)
      @config.certificates.find do |c|
        c['name'] == name || c['domains'].first == name
      end
    end

    def request_certificate(cert_config)
      domains = cert_config['domains']
      provider_name = cert_config['dns_provider']
      dns_alias = cert_config['dns_alias']
      env = effective_environment(cert_config)
      cert_name = cert_config['name'] || domains.first

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
        return
      end

      # Use certbot with manual hooks
      run_certbot_with_hooks(domains, provider, dns_alias, cert_config, env)
    end

    def certificate_exists?(cert_config)
      cert_name = cert_config['name'] || cert_config['domains'].first
      cert_path = File.join(@config.cert_dir, cert_name, 'cert.pem')
      File.exist?(cert_path)
    end

    def run_certbot_with_hooks(domains, provider, dns_alias, cert_config, environment)
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
        '--agree-tos',
        '--non-interactive'
      ]

      cmd += ['--email', @config.email] if @config.email
      cmd += ['--cert-name', cert_config['name']] if cert_config['name']
      cmd += domain_args

      # Set ACME server based on environment
      if environment == :staging
        cmd += ['--server', ACME_SERVERS[:staging]]
      else
        cmd += ['--server', ACME_SERVERS[:production]]
      end

      @logger.debug("Running: #{cmd.join(' ')}")

      # Set environment for hooks
      env = {
        'CERT_MANAGER_PROVIDER' => provider.name,
        'CERT_MANAGER_CONFIG' => @config.instance_variable_get(:@path),
        'CERT_MANAGER_PROPAGATION_WAIT' => @config.propagation_wait.to_s
      }
      env['CERT_MANAGER_DNS_ALIAS'] = dns_alias if dns_alias

      success = system(env, *cmd)

      unless success
        raise "Certbot command failed with exit code: #{$?.exitstatus}"
      end

      @logger.info("Certificate obtained successfully!")
    end

    def auth_hook_script(provider, dns_alias)
      script = <<~BASH
        #!/bin/bash
        #{RbConfig.ruby} -r '#{__dir__}/lib/dns_providers' -e '
          require "yaml"
          config = YAML.safe_load(File.read(ENV["CERT_MANAGER_CONFIG"]))
          provider_config = config["dns_providers"][ENV["CERT_MANAGER_PROVIDER"]]
          provider = CertManager::DNSProviders.create(
            provider_config["type"],
            ENV["CERT_MANAGER_PROVIDER"],
            provider_config.reject { |k, _| k == "type" }
          )

          domain = ENV["CERTBOT_DOMAIN"]
          validation = ENV["CERTBOT_VALIDATION"]
          record_name = ENV["CERT_MANAGER_DNS_ALIAS"] || "_acme-challenge.#{domain}"

          puts "Adding TXT record: #{record_name} = #{validation}"
          record_id = provider.add_txt_record(domain, record_name, validation)

          # Store record ID for cleanup
          File.write("/tmp/certbot_record_#{domain}", record_id.to_s)

          # Wait for propagation
          sleep(ENV["CERT_MANAGER_PROPAGATION_WAIT"].to_i)
        '
      BASH

      write_temp_script('auth_hook', script)
    end

    def cleanup_hook_script(provider, dns_alias)
      script = <<~BASH
        #!/bin/bash
        #{RbConfig.ruby} -r '#{__dir__}/lib/dns_providers' -e '
          require "yaml"
          config = YAML.safe_load(File.read(ENV["CERT_MANAGER_CONFIG"]))
          provider_config = config["dns_providers"][ENV["CERT_MANAGER_PROVIDER"]]
          provider = CertManager::DNSProviders.create(
            provider_config["type"],
            ENV["CERT_MANAGER_PROVIDER"],
            provider_config.reject { |k, _| k == "type" }
          )

          domain = ENV["CERTBOT_DOMAIN"]
          validation = ENV["CERTBOT_VALIDATION"]

          record_id_file = "/tmp/certbot_record_#{domain}"
          if File.exist?(record_id_file)
            record_id = File.read(record_id_file).strip
            puts "Removing TXT record: #{record_id}"
            provider.remove_txt_record(domain, record_id, validation)
            File.delete(record_id_file)
          end
        '
      BASH

      write_temp_script('cleanup_hook', script)
    end

    def write_temp_script(name, content)
      path = "/tmp/cert_manager_#{name}_#{$$}.sh"
      File.write(path, content)
      File.chmod(0o755, path)
      path
    end

    def certificate_needs_renewal?(cert_config, days_threshold: 30)
      cert_name = cert_config['name'] || cert_config['domains'].first
      cert_path = File.join(@config.cert_dir, cert_name, 'cert.pem')

      return true unless File.exist?(cert_path)

      expiry = get_certificate_expiry(cert_path)
      return true unless expiry

      days_remaining = (expiry - Time.now) / 86400
      days_remaining < days_threshold
    end

    def get_certificate_expiry(cert_path)
      output = `openssl x509 -enddate -noout -in "#{cert_path}" 2>/dev/null`
      return nil unless $?.success?

      if output =~ /notAfter=(.+)/
        Time.parse($1)
      end
    rescue ArgumentError
      nil
    end

    def print_certificate_status(cert_config)
      cert_name = cert_config['name'] || cert_config['domains'].first
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
          days_left = ((expiry - Time.now) / 86400).to_i
          status = days_left < 30 ? 'NEEDS RENEWAL' : 'OK'
          puts "  Expires: #{expiry.strftime('%Y-%m-%d')} (#{days_left} days)"
          puts "  Status: #{status}"
        else
          puts "  Status: UNABLE TO READ CERTIFICATE"
        end
      else
        puts "  Status: NOT ISSUED"
      end
    end

    def print_environment_info
      if @environment_override
        puts "Environment override: #{@environment_override.to_s.upcase}"
      else
        puts "Default environment: #{@config.default_environment.to_s.upcase}"
      end
      puts ""
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

      # Directory where certificates are stored (optional)
      cert_dir: /etc/letsencrypt/live

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

      # Certificates to manage
      certificates:
        # Production certificate (uses default environment)
        - name: internal-server
          domains:
            - internal.example.com
          dns_provider: cloudflare_main

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
    yes: false
  }

  parser = OptionParser.new do |opts|
    opts.banner = "Usage: #{$PROGRAM_NAME} [options] <command> [args]"
    opts.separator ""
    opts.separator "Commands:"
    opts.separator "  request <name>    Request a new certificate"
    opts.separator "  renew             Renew certificates due for renewal"
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

    opts.on('-f', '--force', 'Force renewal even if not due') do
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

    opts.on('-v', '--version', 'Show version') do
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
        skip_prompts: options[:yes]
      )
      manager.request(cert_name)
    rescue StandardError => e
      puts "Error: #{e.message}"
      exit 1
    end

  when 'renew'
    begin
      manager = CertManager::Manager.new(
        config_path: options[:config],
        dry_run: options[:dry_run],
        environment: options[:environment],
        quiet: options[:quiet],
        skip_prompts: options[:yes]
      )
      manager.renew(force: options[:force])
    rescue StandardError => e
      puts "Error: #{e.message}"
      exit 1
    end

  when 'list'
    begin
      manager = CertManager::Manager.new(
        config_path: options[:config],
        environment: options[:environment]
      )
      manager.print_environment_info
      manager.list
    rescue StandardError => e
      puts "Error: #{e.message}"
      exit 1
    end

  when 'verify'
    begin
      manager = CertManager::Manager.new(config_path: options[:config])
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
