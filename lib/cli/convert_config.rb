# frozen_string_literal: true

require 'yaml'

module CertManager
  module CLI
    # Implements the convert-config command
    class ConvertConfig
      def initialize(options)
        @options = options
      end

      def run
        source = source_path
        dest = dest_path(source)
        v1 = read_v1(source)
        dry_run = @options[:dry_run]

        store = nil
        unless dry_run
          confirm_overwrite(dest)
          store = SecretStore.new(SecretStore.key_path_for(dest), create: true)
        end
        encryptor = dry_run ? ->(value) { "#{SecretStore.mask(value)} (will be encrypted)" } : store.method(:encrypt)
        result = ConfigMigrator.new(v1, encryptor: encryptor).migrate

        return print_preview(source, dest, result) if dry_run

        write(dest, result)
        print_summary(source, dest, result)
      end

      private

      def source_path
        path = @options[:config] || ENV[Config::ENV_VAR]
        path = path.to_s.empty? ? Config::LEGACY_CONFIG_PATH : File.expand_path(path)
        raise "Configuration file not found: #{path}" unless File.exist?(path)

        path
      end

      def dest_path(source)
        dest = File.expand_path(@options[:output] || File.join(File.dirname(source), 'config.v2.yml'))
        raise 'Output path is the same as the source; use --output to choose another file' if dest == source

        dest
      end

      def read_v1(source)
        FilePermissions.check(source)
        doc = YAML.safe_load(File.read(source), permitted_classes: [Symbol])
        raise ConfigError, "Configuration file is empty or invalid: #{source}" unless doc.is_a?(Hash)
        raise "#{source} is already a v2 configuration; nothing to convert" if doc.fetch('version', 1) != 1

        doc
      end

      def confirm_overwrite(dest)
        return unless File.exist?(dest)
        return if Prompt.confirm("#{dest} already exists. Overwrite?", assume_yes: @options[:yes])

        raise 'Aborted; existing v2 configuration left untouched'
      end

      def write(dest, result)
        writer = ConfigWriter.new(dest, create: true)
        writer.data.replace(result.document)
        writer.save
        Config.new(dest, warn_legacy: false) # validates and proves the secrets decrypt
      rescue ConfigError => e
        raise "Converted file #{dest} failed validation: #{e.message}"
      end

      def print_preview(source, dest, result)
        puts "Dry run: would convert #{source} -> #{dest}"
        puts "Would create #{SecretStore.key_path_for(dest)} if missing"
        puts
        puts YAML.dump(result.document)
        print_notes(result)
      end

      def print_summary(source, dest, result)
        puts "Converted #{source} -> #{dest}"
        puts "Encryption key: #{SecretStore.key_path_for(dest)}  (back this up; secrets cannot be recovered without it)"
        puts "Encrypted #{result.encrypted.size} secret(s): #{result.encrypted.join(', ')}" unless result.encrypted.empty?
        print_notes(result)
        puts
        puts "The old file was left untouched. After running `#{CLI.program} verify` successfully,"
        puts "delete or archive #{source} (it still holds plaintext API keys)."
        return unless $stdin.tty? && Prompt.confirm('Run verify now?')

        Manager.new(config_path: dest).verify_providers
      end

      def print_notes(result)
        result.zones.each { |name, zones| puts "Zones for #{name}: #{zones.empty? ? '(none)' : zones.join(', ')}" }
        unless result.explicit_certs.empty?
          puts "Certificates keeping an explicit dns_provider (zones alone are ambiguous): #{result.explicit_certs.join(', ')}"
        end
        result.warnings.each { |w| warn "Warning: #{w}" }
      end
    end
  end
end
