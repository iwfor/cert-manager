# frozen_string_literal: true

require 'test/unit'
require 'tmpdir'
require 'fileutils'
require 'json'
require 'yaml'
require 'stringio'

# Load the cert_manager module without executing the CLI block
require_relative '../cert_manager'

module TestFixtures
  # Write a minimal valid config file and return its path
  def write_config(dir, overrides = {})
    config = {
      'email' => 'test@example.com',
      'config_dir' => File.join(dir, 'certbot'),
      'work_dir' => File.join(dir, 'certbot', 'work'),
      'logs_dir' => File.join(dir, 'certbot', 'logs'),
      'dns_providers' => {
        'test_cf' => { 'type' => 'cloudflare', 'api_token' => 'fake-token' }
      },
      'certificates' => [
        {
          'name' => 'webserver',
          'domains' => ['www.example.com'],
          'dns_provider' => 'test_cf'
        }
      ]
    }.merge(overrides)

    path = File.join(dir, 'config.yml')
    File.write(path, YAML.dump(config))
    path
  end

  # Capture all output written to STDOUT (including Logger)
  def capture_output
    reader, writer = IO.pipe
    original = STDOUT.dup
    STDOUT.reopen(writer)
    $stdout = STDOUT
    yield
    STDOUT.reopen(original)
    $stdout = STDOUT
    writer.close
    reader.read
  ensure
    reader&.close unless reader&.closed?
  end

  # Create a Manager with quiet + dry_run defaults pointing at a temp config
  def build_manager(config_path, dry_run: true, quiet: true, **opts)
    CertManager::Manager.new(
      config_path: config_path,
      dry_run: dry_run,
      quiet: quiet,
      skip_prompts: true,
      **opts
    )
  end
end
