# frozen_string_literal: true

require 'yaml'
require 'tempfile'
require 'fileutils'
require 'digest'
require_relative 'config'
require_relative 'secret_store'

module CertManager
  # Reads and rewrites a v2 configuration file for the management commands
  # (add-provider, add-zone, ...). Works on the raw document so encrypted
  # secrets are never decrypted just to be written back. Comments in the
  # file are not preserved.
  class ConfigWriter
    BACKUPS_KEPT = 10

    attr_reader :path, :data

    # @param path [String] Path to the v2 config file
    # @param create [Boolean] Start from an empty v2 document if the file does not exist
    def initialize(path, create: false)
      @path = File.expand_path(path)
      @digest = file_digest
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
      providers.select { |_, settings| settings.is_a?(Hash) }
               .transform_values { |settings| (settings['zones'] || []).map { |z| Config.normalize_zone(z) } }
    end

    # True if any credential in the file is an ENC[...] secret
    def encrypted_values?
      providers.values.grep(Hash).any? { |s| (s['credentials'] || {}).values.any? { |v| SecretStore.encrypted?(v) } }
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
    # timestamped backup of the previous file (the newest BACKUPS_KEPT are kept).
    # A symlinked config is written through to its target. Concurrent edits are
    # detected: if the file changed since it was read, nothing is written.
    # @return [String, nil] backup path, if one was made
    # @raise [ConfigError] if the file was modified by someone else meanwhile
    def save
      target = real_path
      FileUtils.mkdir_p(File.dirname(target), mode: 0o700)
      with_lock(target) do
        unless file_digest(target) == @digest
          raise ConfigError, "#{target} was modified by another process while editing; nothing was saved. Re-run the command."
        end

        backup = backup_existing(target)
        write_atomically(target)
        prune_backups(target)
        @digest = file_digest(target)
        backup
      end
    end

    private

    def real_path
      File.symlink?(@path) ? File.realpath(@path) : @path
    rescue Errno::ENOENT
      @path
    end

    def file_digest(path = real_path)
      File.exist?(path) ? Digest::SHA256.file(path).hexdigest : nil
    end

    def with_lock(target)
      File.open("#{target}.lock", File::CREAT | File::WRONLY, 0o600) do |lock|
        lock.flock(File::LOCK_EX)
        yield
      end
    end

    def write_atomically(target)
      dir = File.dirname(target)
      Tempfile.create(['.config', '.tmp'], dir) do |tmp|
        tmp.chmod(0o600)
        tmp.write(YAML.dump(@data))
        tmp.flush
        tmp.fsync
        File.rename(tmp.path, target)
      end
      File.open(dir) { |d| d.fsync }
    rescue SystemCallError
      nil # directory fsync is best effort
    end

    def load_document(create)
      if File.exist?(@path)
        doc = Config.read_document(@path)
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

    def backup_existing(target)
      return unless File.exist?(target)

      stamp = Time.now.strftime('%Y%m%d%H%M%S%L')
      backup = "#{target}.#{stamp}.bak"
      backup = "#{target}.#{stamp}-#{rand(1000)}.bak" while File.exist?(backup)
      FileUtils.cp(target, backup)
      File.chmod(0o600, backup)
      backup
    end

    def prune_backups(target)
      Dir["#{target}.*.bak"].sort.reverse.drop(BACKUPS_KEPT).each { |old| File.delete(old) }
    end
  end
end
