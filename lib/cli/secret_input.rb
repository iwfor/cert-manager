# frozen_string_literal: true

module CertManager
  module CLI
    # Where a command gets secret values from. Secrets are never accepted as
    # command-line arguments (they would show up in `ps` and shell history):
    # a hidden prompt, one line per secret on stdin, or an environment variable.
    class SecretInput
      OPTIONS = [
        CLI.option(:key_stdin, long: '--key-stdin', desc: 'Read secret value(s) from stdin, one per line'),
        CLI.option(:key_env, long: '--key-env', arg: 'VAR', desc: 'Read the secret from environment variable VAR (single secret only)')
      ].freeze

      # @param options [Hash] parsed CLI options
      # @param count [Integer] how many secrets will be read
      # @raise [UsageError] on conflicting or unusable input modes
      def initialize(options, count)
        @env = options[:key_env]
        @stdin = options[:key_stdin]
        raise UsageError, '--key-stdin and --key-env cannot be used together' if @env && @stdin
        raise UsageError, "--key-env supports a single secret, but #{count} are needed; use --key-stdin" if @env && count > 1
      end

      # @param label [String] shown in the prompt and in errors
      # @return [String]
      def read(label)
        value = if @env then ENV[@env].to_s
                elsif @stdin then $stdin.gets.to_s.chomp
                else Prompt.secret("Enter #{label}")
                end
        raise "No value provided for #{label}#{" (environment variable #{@env} is empty or unset)" if @env}" if value.empty?

        value
      end
    end
  end
end
