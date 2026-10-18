# frozen_string_literal: true

require 'io/console'

module CertManager
  module CLI
    # Interactive input helpers. All of them are safe on EOF (non-interactive
    # input yields the default / empty answer instead of raising).
    module Prompt
      module_function

      # Ask a yes/no question; the default is "no"
      # @param assume_yes [Boolean] answer yes without asking (--yes)
      def confirm(message, assume_yes: false)
        return true if assume_yes

        $stderr.print "#{message} [y/N] "
        $stdin.gets.to_s.strip.downcase == 'y'
      end

      # Ask for a visible value
      # @return [String] the answer, or default when blank / on EOF
      def ask(message, default: nil)
        $stderr.print default ? "#{message} [#{default}]: " : "#{message}: "
        answer = $stdin.gets.to_s.strip
        answer.empty? ? default.to_s : answer
      end

      # Ask for a secret without echoing it. Reads a plain line when stdin is
      # not a terminal, so values can be piped in.
      def secret(message)
        $stderr.print "#{message}: "
        value = $stdin.tty? ? $stdin.noecho(&:gets) : $stdin.gets
        $stderr.puts if $stdin.tty?
        value.to_s.chomp
      end
    end
  end
end
