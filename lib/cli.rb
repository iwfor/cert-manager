# frozen_string_literal: true

require 'optparse'
require_relative 'cli/prompt'

module CertManager
  # Command-line interface: a registry of commands, each with its own
  # arguments, options and help. Help text and shell completions are
  # generated from this registry, so new commands and flags are defined
  # here once and show up everywhere.
  module CLI
    EXIT_OK = 0
    EXIT_ERROR = 1
    EXIT_USAGE = 2

    REVOCATION_REASONS = %w[unspecified keycompromise cacompromise affiliationchanged superseded cessationofoperation].freeze

    # Raised to print help/version text and exit successfully
    class HelpRequested < StandardError
      attr_reader :text

      def initialize(text)
        @text = text
        super('help requested')
      end
    end

    # Raised for bad command lines; reported with exit status 2
    class UsageError < StandardError; end

    # A command-line flag. `key` is where its value lands in the options hash.
    # `values` lists the allowed values (also used for completion).
    Option = Struct.new(:key, :short, :long, :arg, :desc, :values, :multiple, keyword_init: true) do
      def flags
        [short, long].compact
      end

    end

    # A positional argument. `kind` drives completion (:certificate, :provider, :zone, :shell, :type, :file, nil)
    Arg = Struct.new(:name, :kind, :required, :desc, keyword_init: true)

    Command = Struct.new(:name, :group, :summary, :args, :options, :globals, :examples, :description, :handler, keyword_init: true) do
      def usage(program)
        parts = args.map { |a| a.required ? "<#{a.name}>" : "[#{a.name}]" }
        "#{program} #{name} #{parts.join(' ')}".strip
      end
    end

    # What a handler gets: parsed options, positional args and a Manager factory
    Context = Struct.new(:options, :args, keyword_init: true) do
      def manager
        Manager.new(
          config_path: options[:config],
          dry_run: options[:dry_run],
          environment: options[:environment],
          quiet: options[:quiet],
          skip_prompts: options[:yes],
          verbose: options[:verbose]
        )
      end
    end

    GROUPS = {
      certificates: 'Certificate commands',
      configuration: 'Configuration commands',
      tools: 'Tools'
    }.freeze

    # Options accepted by every command (help only lists the ones a command declares in `globals`)
    GLOBAL_OPTIONS = {
      config: Option.new(key: :config, short: '-c', long: '--config', arg: 'PATH',
                         desc: 'Path to configuration file (default: $CERT_MANAGER_CONFIG, then config.v2.yml, then config.yml)'),
      dry_run: Option.new(key: :dry_run, short: '-n', long: '--dry-run',
                          desc: 'Show what would be done without making changes'),
      force: Option.new(key: :force, short: '-f', long: '--force',
                        desc: 'Reissue even if not due (request/renew); clear recorded failure state (deploy)'),
      staging: Option.new(key: :staging, short: '-s', long: '--staging',
                          desc: "Use Let's Encrypt staging (test certificates)"),
      production: Option.new(key: :production, short: '-p', long: '--production',
                             desc: "Use Let's Encrypt production (real certificates)"),
      quiet: Option.new(key: :quiet, short: '-q', long: '--quiet', desc: 'Only output errors (for cron jobs)'),
      yes: Option.new(key: :yes, short: '-y', long: '--yes', desc: 'Skip confirmation prompts (for automation)'),
      verbose: Option.new(key: :verbose, short: '-v', long: '--verbose', desc: 'Show extra detail')
    }.freeze

    ALL_GLOBALS = GLOBAL_OPTIONS.keys.freeze

    @commands = {}

    class << self
      attr_reader :commands

      # Define a command
      # @param name [String]
      # @param group [Symbol] key of GROUPS
      # @param globals [Array<Symbol>] global options this command honors (for help)
      # @yieldparam ctx [Context]
      def command(name, group:, summary:, args: [], options: [], globals: [], examples: [], description: nil, &handler)
        @commands[name] = Command.new(name: name, group: group, summary: summary, args: args, options: options,
                                      globals: globals, examples: examples, description: description, handler: handler)
      end

      def arg(name, kind = nil, required: true, desc: nil)
        Arg.new(name: name, kind: kind, required: required, desc: desc)
      end

      def option(key, long:, short: nil, arg: nil, desc:, values: nil, multiple: false)
        Option.new(key: key, short: short, long: long, arg: arg, desc: desc, values: values, multiple: multiple)
      end

      def program
        File.basename($PROGRAM_NAME)
      end

      # Run the CLI
      # @param argv [Array<String>]
      # @return [Integer] process exit status
      def run(argv)
        argv = argv.dup
        options = default_options
        # Global flags may precede the command (cron lines like `-q -y renew`)
        pre_command_parser(options).order!(argv)
        name = argv.shift
        return print_help && EXIT_USAGE if name.nil?

        cmd = @commands[name] or raise UsageError, "Unknown command '#{name}'"
        parser = command_parser(cmd, options)
        parser.parse!(argv)
        finalize_environment!(options)
        validate_args!(cmd, argv)
        cmd.handler.call(Context.new(options: options, args: argv))
        EXIT_OK
      rescue HelpRequested => e
        puts e.text
        EXIT_OK
      rescue OptionParser::ParseError, UsageError => e
        warn "Error: #{e.message}"
        warn "Run '#{program} help#{" #{cmd.name}" if cmd}' for usage."
        EXIT_USAGE
      rescue Interrupt
        warn
        130
      rescue StandardError => e
        warn "Error: #{e.message}"
        EXIT_ERROR
      end

      # Top-level help text
      def help_text
        lines = ["Usage: #{program} [options] <command> [args]", '']
        GROUPS.each do |group, title|
          cmds = @commands.values.select { |c| c.group == group }
          next if cmds.empty?

          lines << "#{title}:"
          width = cmds.map { |c| signature(c).length }.max
          cmds.each { |c| lines << "  #{signature(c).ljust(width)}  #{c.summary}" }
          lines << ''
        end
        lines << 'Global options:'
        lines.concat(option_lines(ALL_GLOBALS.map { |k| GLOBAL_OPTIONS[k] } + [version_option, help_option]))
        lines << ''
        lines << "Run '#{program} help <command>' for details on a command."
        lines.join("\n")
      end

      # Help text for one command
      def command_help(cmd)
        lines = ["Usage: #{cmd.usage(program)} [options]", '', cmd.summary]
        lines.concat(['', cmd.description]) if cmd.description
        arg_descs = cmd.args.select(&:desc)
        unless arg_descs.empty?
          lines << '' << 'Arguments:'
          arg_descs.each { |a| lines << "  #{a.name.ljust(14)}#{a.desc}" }
        end
        opts = cmd.options + cmd.globals.map { |k| GLOBAL_OPTIONS.fetch(k) } + [help_option]
        lines << '' << 'Options:'
        lines.concat(option_lines(opts))
        unless cmd.examples.empty?
          lines << '' << 'Examples:'
          cmd.examples.each { |e| lines << "  #{program} #{e}" }
        end
        lines.join("\n")
      end

      private

      def print_help
        puts help_text
        true
      end

      def default_options
        { config: nil, dry_run: false, force: false, environment: nil, quiet: false, yes: false, verbose: false,
          staging: false, production: false }
      end

      def version_option
        Option.new(key: :version, short: '-V', long: '--version', desc: 'Show version')
      end

      def help_option
        Option.new(key: :help, short: '-h', long: '--help', desc: 'Show help')
      end

      public :version_option, :help_option

      def signature(cmd)
        parts = cmd.args.map { |a| a.required ? "<#{a.name}>" : "[#{a.name}]" }
        [cmd.name, *parts].join(' ')
      end

      def option_lines(opts)
        specs = opts.map do |o|
          [o.short, "#{o.long}#{" #{o.arg}" if o.arg}"].compact.join(', ')
        end
        width = specs.map(&:length).max
        opts.zip(specs).map { |o, spec| "  #{spec.ljust(width)}  #{o.desc}" }
      end

      # Parser for flags that appear before the command name
      def pre_command_parser(options)
        OptionParser.new do |p|
          register_globals(p, options)
          register(p, version_option, options) { raise HelpRequested, "CertManager v#{CertManager::VERSION}" }
          p.on('-h', '--help') { raise HelpRequested, help_text }
          p.on('-r', '--reason REASON', REVOCATION_REASONS) { |v| options[:reason] = v }
        end
      end

      def command_parser(cmd, options)
        OptionParser.new do |p|
          register_globals(p, options)
          cmd.options.each { |o| register(p, o, options) }
          p.on('-h', '--help') { raise HelpRequested, command_help(cmd) }
        end
      end

      def register_globals(parser, options)
        GLOBAL_OPTIONS.each_value { |o| register(parser, o, options) }
      end

      def register(parser, opt, options, &block)
        spec = opt.long + (opt.arg ? " #{opt.arg}" : '')
        args = [opt.short, spec, opt.values].compact
        parser.on(*args) do |value|
          if block then block.call
          elsif opt.multiple then (options[opt.key] ||= []) << value
          else options[opt.key] = (opt.arg ? value : true)
          end
        end
      end

      def finalize_environment!(options)
        raise UsageError, '--staging and --production cannot be used together' if options[:staging] && options[:production]

        options[:environment] = :staging if options[:staging]
        options[:environment] = :production if options[:production]
      end

      def validate_args!(cmd, args)
        required = cmd.args.count(&:required)
        if args.size < required
          missing = cmd.args.select(&:required)[args.size].name
          raise UsageError, "Missing <#{missing}> (usage: #{cmd.usage(program)})"
        end
        return if args.size <= cmd.args.size

        raise UsageError, "Unexpected argument '#{args[cmd.args.size]}' (usage: #{cmd.usage(program)})"
      end
    end
  end
end

require_relative 'cli/convert_config'
require_relative 'cli/commands'
require_relative 'cli/provider_commands'
require_relative 'cli/completion_commands'
