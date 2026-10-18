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
          store = open_store(dest)
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
        doc = Config.read_document(source)
        version = doc.fetch('version', 1)
        return doc if version == 1

        if version == Config::CURRENT_VERSION
          raise "#{source} is already a v2 configuration, so there is nothing to convert.\n" \
                "To use it, nothing more is needed: pass it with `-c #{source}` or set $#{Config::ENV_VAR}, " \
                "or rename it to #{Config::DEFAULT_CONFIG_PATH} (the name looked up by default).\n" \
                "To convert a v1 file, point at it with `#{CLI.program} -c /path/to/config.yml convert-config`."
        end

        raise "Unsupported config version #{version.inspect} in #{source} (convert-config reads version 1 files; " \
              "v2 files need no conversion). Check the `version:` key."
      end

      def confirm_overwrite(dest)
        return unless File.exist?(dest)
        return if Prompt.confirm("#{dest} already exists. Overwrite?", assume_yes: @options[:yes])

        raise 'Aborted; existing v2 configuration left untouched'
      end

      def write(dest, result)
        writer = ConfigWriter.new(dest, create: true)
        writer.data.replace(result.document)
        backup = writer.save
        begin
          Config.new(dest, warnings: false) # validates and proves the secrets decrypt
        rescue ConfigError => e
          restore(dest, backup)
          raise "Converted file failed validation, so #{dest} was #{backup ? 'restored' : 'removed'} and your v1 config remains in use: #{e.message}"
        end
      end

      # Undo a write whose result does not validate, so the invalid file cannot shadow the v1 config
      def restore(dest, backup)
        backup ? FileUtils.cp(backup, dest) : File.delete(dest)
      end

      def open_store(dest)
        SecretStore.new(SecretStore.key_path_for(dest), create: true)
      rescue SecretStore::Error => e
        raise ConfigError, e.message
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
