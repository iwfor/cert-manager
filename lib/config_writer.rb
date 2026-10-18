# frozen_string_literal: true

require 'yaml'
require 'tempfile'
require 'fileutils'
require_relative 'config'
require_relative 'secret_store'

module CertManager
  # Reads and rewrites a v2 configuration file for the management commands
  # (add-provider, add-zone, ...). Works on the raw document so encrypted
  # secrets are never decrypted just to be written back. Comments in the
  # file are not preserved.
  class ConfigWriter
    attr_reader :path, :data

    # @param path [String] Path to the v2 config file
    # @param create [Boolean] Start from an empty v2 document if the file does not exist
    def initialize(path, create: false)
      @path = File.expand_path(path)
      @data = load_document(create)
    end

    # Raw `providers` mapping (name => settings)
    def providers
      @data['providers'] ||= {}
    end

    # Raw settings of a provider
    # @raise [ConfigError] if it is not configured
    def provider!(name)
      providers[name] or raise ConfigError, "Unknown provider '#{name}' (configured: #{providers.keys.join(', ').then { |n| n.empty? ? 'none' : n }})"
    end

    # Normalized zones of every provider, e.g. { 'cf' => ['example.com'] }
    def zones_by_provider
      providers.transform_values { |settings| (settings['zones'] || []).map { |z| Config.normalize_zone(z) } }
    end

    # True if any credential in the file is an ENC[...] secret
    def encrypted_values?
      providers.values.any? { |s| (s['credentials'] || {}).values.any? { |v| SecretStore.encrypted?(v) } }
    end

    # Open the file's secret store, creating the key only when nothing is
    # encrypted yet (a fresh key would orphan existing secrets).
    def secret_store
      key_path = SecretStore.key_path_for(@path)
      SecretStore.new(key_path, create: !encrypted_values?)
    rescue SecretStore::Error, SecurityError => e
      raise ConfigError, e.message
    end

    # A provider's credentials with secrets decrypted
    def plain_credentials(name, store)
      (provider!(name)['credentials'] || {}).transform_values { |v| SecretStore.encrypted?(v) ? store.decrypt(v) : v }
    end

    # Atomically write the document with owner-only permissions, keeping a
    # timestamped backup of the previous file.
    # @return [String, nil] backup path, if one was made
    def save
      FileUtils.mkdir_p(File.dirname(@path), mode: 0o700)
      backup = backup_existing
      Tempfile.create(['.config', '.tmp'], File.dirname(@path)) do |tmp|
        tmp.chmod(0o600)
        tmp.write(YAML.dump(@data))
        tmp.flush
        tmp.fsync
        File.rename(tmp.path, @path)
      end
      backup
    end

    private

    def load_document(create)
      if File.exist?(@path)
        doc = YAML.safe_load(File.read(@path), permitted_classes: [Symbol])
        raise ConfigError, "Configuration file is empty or invalid: #{@path}" unless doc.is_a?(Hash)
        unless doc['version'] == Config::CURRENT_VERSION
          raise ConfigError, "#{@path} is not a v2 config; run `cert_manager.rb convert-config` first"
        end

        doc
      elsif create
        { 'version' => Config::CURRENT_VERSION }
      else
        raise ConfigError, "Configuration file not found: #{@path}\nRun `cert_manager.rb init` to create one."
      end
    end

    def backup_existing
      return unless File.exist?(@path)

      backup = "#{@path}.#{Time.now.strftime('%Y%m%d%H%M%S')}.bak"
      FileUtils.cp(@path, backup)
      File.chmod(0o600, backup)
      backup
    end
  end
end
