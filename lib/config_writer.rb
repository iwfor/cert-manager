# frozen_string_literal: true

require 'yaml'
require 'tempfile'
require 'fileutils'
require_relative 'config'

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
        raise ConfigError, "Configuration file not found: #{@path}"
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
