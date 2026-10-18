# frozen_string_literal: true

require_relative '../config_writer'
require_relative '../secret_store'
require_relative '../config_migrator'

module CertManager
  module CLI
    CERT_GLOBALS = %i[config dry_run force staging production quiet yes verbose].freeze

    command 'request', group: :certificates, summary: 'Request a new certificate',
            args: [arg('name', :certificate, desc: 'Certificate name (or first domain) from the config')],
            globals: CERT_GLOBALS,
            examples: ['--staging request webserver', 'request webserver'],
            description: 'Create a staging certificate first (--staging), then switch to production.' do |ctx|
      ctx.manager.request(ctx.args.first, force: ctx.options[:force])
    end

    command 'deploy', group: :certificates, summary: 'Deploy a certificate to its configured targets',
            args: [arg('name', :certificate)],
            globals: %i[config dry_run force quiet yes verbose],
            description: 'With --force, clears the recorded deploy failure state first.' do |ctx|
      ctx.manager.deploy(ctx.args.first, force: ctx.options[:force])
    end

    command 'renew', group: :certificates, summary: 'Renew certificate(s) due for renewal',
            args: [arg('name', :certificate, required: false, desc: 'Renew only this certificate')],
            globals: CERT_GLOBALS,
            examples: ['--quiet --yes renew   # daily cron job'] do |ctx|
      ctx.manager.renew(cert_name: ctx.args.first, force: ctx.options[:force])
    end

    command 'revoke', group: :certificates, summary: 'Revoke a certificate',
            args: [arg('name', :certificate)],
            options: [option(:reason, long: '--reason', short: '-r', arg: 'REASON', values: REVOCATION_REASONS,
                             desc: "Revocation reason (#{REVOCATION_REASONS.join(', ')})")],
            globals: %i[config dry_run staging production quiet yes verbose] do |ctx|
      ctx.manager.revoke(ctx.args.first, reason: ctx.options[:reason])
    end

    command 'cleanup', group: :certificates, summary: 'Remove leftover ACME challenge DNS records',
            args: [arg('name', :certificate)],
            globals: %i[config quiet verbose] do |ctx|
      ctx.manager.cleanup(ctx.args.first)
    end

    command 'list', group: :certificates, summary: 'List configured certificates and their status',
            globals: %i[config staging production verbose] do |ctx|
      manager = ctx.manager
      manager.print_environment_info
      manager.list
    end

    command 'verify', group: :configuration, summary: 'Verify DNS provider credentials',
            globals: %i[config verbose] do |ctx|
      ctx.manager.verify_providers
    end

    command 'init', group: :configuration, summary: 'Create a new configuration file and encryption key',
            options: [option(:email, long: '--email', arg: 'ADDRESS', desc: "Let's Encrypt notification email")],
            globals: %i[config yes],
            description: "Creates config.v2.yml (mode 0600) and cert-manager.key next to it. Then add a\n" \
                         'provider with add-provider.' do |ctx|
      path = Config.default_write_path(ctx.options[:config])
      if File.exist?(path) && !Prompt.confirm("#{path} already exists. Overwrite?", assume_yes: ctx.options[:yes])
        raise 'Aborted; existing configuration left untouched'
      end

      email = ctx.options[:email] || ($stdin.tty? ? Prompt.ask("Email for Let's Encrypt notifications") : '')
      email = 'admin@example.com' if email.empty?

      writer = ConfigWriter.new(path, create: true)
      writer.data.replace(
        'version' => Config::CURRENT_VERSION, 'email' => email, 'certbot_path' => 'certbot', 'log_level' => 'INFO',
        'propagation_wait' => 60, 'environment' => 'production', 'providers' => {}, 'certificates' => []
      )
      writer.save

      key_path = SecretStore.key_path_for(path)
      SecretStore.generate_key(key_path) unless File.exist?(key_path)

      puts "Configuration written to: #{path}"
      puts "Encryption key:           #{key_path}  (back this up; secrets cannot be recovered without it)"
      puts "Email:                    #{email}  (edit the file to change it)" if email == 'admin@example.com'
      puts
      puts "Next: #{CLI.program} add-provider NAME --type cloudflare"
    end

    command 'convert-config', group: :configuration, summary: 'Convert a v1 config.yml to the v2 format',
            options: [option(:output, long: '--output', arg: 'PATH',
                             desc: 'Where to write the v2 file (default: config.v2.yml next to the source)')],
            globals: %i[config dry_run yes],
            description: "Reads the old config (-c, $CERT_MANAGER_CONFIG, or ~/.config/cert_manager/config.yml),\n" \
                         "writes a v2 file with API keys encrypted using cert-manager.key (created if needed),\n" \
                         "and infers each provider's zones from your certificates. The old file is left untouched.",
            examples: ['convert-config --dry-run', 'convert-config'] do |ctx|
      ConvertConfig.new(ctx.options).run
    end

    command 'help', group: :tools, summary: 'Show help for a command',
            args: [arg('command', :command, required: false)] do |ctx|
      name = ctx.args.first
      if name
        cmd = CLI.commands[name] or raise UsageError, "Unknown command '#{name}'"
        puts CLI.command_help(cmd)
      else
        puts CLI.help_text
      end
    end
  end
end
