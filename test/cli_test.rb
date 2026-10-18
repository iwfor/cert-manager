# frozen_string_literal: true

require_relative 'test_helper'

class CLITest < Test::Unit::TestCase
  def setup
    @dir = Dir.mktmpdir('cert_manager_cli')
    @config = File.join(@dir, 'config.v2.yml')
  end

  def teardown
    FileUtils.rm_rf(@dir)
  end

  # Run the CLI in-process, returning [exit_status, stdout, stderr]
  def run_cli(*argv)
    out = StringIO.new
    err = StringIO.new
    old = [$stdout, $stderr, $stdin]
    $stdout = out
    $stderr = err
    $stdin = StringIO.new('')
    status = CertManager::CLI.run(argv)
    [status, out.string, err.string]
  ensure
    $stdout, $stderr, $stdin = old
  end

  def test_no_command_prints_help_and_exits_usage
    status, out, = run_cli
    assert_equal 2, status
    assert_match(/Usage: .* \[options\] <command>/, out)
  end

  def test_help_lists_every_registered_command
    _, out, = run_cli('help')
    CertManager::CLI.commands.each_key { |name| assert_match(/^\s+#{Regexp.escape(name)}\b/, out) }
  end

  def test_command_help_has_usage_and_options
    status, out, = run_cli('help', 'revoke')
    assert_equal 0, status
    assert_match(/Usage: .* revoke <name>/, out)
    assert_match(/--reason REASON/, out)
  end

  def test_dash_h_after_command_shows_command_help
    status, out, = run_cli('renew', '--help')
    assert_equal 0, status
    assert_match(/Usage: .* renew \[name\]/, out)
  end

  def test_unknown_command
    status, _, err = run_cli('bogus')
    assert_equal 2, status
    assert_match(/Unknown command 'bogus'/, err)
  end

  def test_missing_argument
    status, _, err = run_cli('request')
    assert_equal 2, status
    assert_match(/Missing <name>/, err)
  end

  def test_extra_argument
    status, _, err = run_cli('request', 'a', 'b')
    assert_equal 2, status
    assert_match(/Unexpected argument 'b'/, err)
  end

  def test_staging_and_production_conflict
    status, _, err = run_cli('-s', '-p', 'list')
    assert_equal 2, status
    assert_match(/cannot be used together/, err)
  end

  def test_invalid_revocation_reason
    status, _, err = run_cli('revoke', 'x', '--reason', 'bogus')
    assert_equal 2, status
    assert_match(/invalid argument/, err)
  end

  def test_version
    status, out, = run_cli('-V')
    assert_equal 0, status
    assert_match(/CertManager v/, out)
  end

  def test_errors_go_to_stderr_with_status_1
    status, out, err = run_cli('-c', File.join(@dir, 'missing.yml'), 'list')
    assert_equal 1, status
    assert_equal '', out
    assert_match(/Configuration file not found/, err)
  end

  def test_global_flags_accepted_before_and_after_command
    [['-c', @config, '-q', 'list'], ['list', '-c', @config, '-q']].each do |argv|
      status, _, err = run_cli(*argv)
      assert_equal 1, status
      assert_match(/Configuration file not found/, err)
    end
  end

  def test_init_creates_config_and_key_owner_only
    status, out, = run_cli('-c', @config, 'init', '--email', 'me@example.org')
    assert_equal 0, status
    assert_match(/add-provider/, out)
    assert_equal 0o600, File.stat(@config).mode & 0o777
    key = File.join(@dir, 'cert-manager.key')
    assert_equal 0o600, File.stat(key).mode & 0o777
    config = CertManager::Config.new(@config)
    assert_equal 'me@example.org', config.email
    assert_equal 2, config.version
  end

  def test_init_does_not_overwrite_without_confirmation
    run_cli('-c', @config, 'init', '--email', 'first@example.org')
    status, _, err = run_cli('-c', @config, 'init', '--email', 'second@example.org')
    assert_equal 1, status
    assert_match(/Aborted/, err)
    assert_equal 'first@example.org', CertManager::Config.new(@config).email
  end

  def test_init_overwrites_with_yes_and_keeps_existing_key
    run_cli('-c', @config, 'init', '--email', 'first@example.org')
    key = File.read(File.join(@dir, 'cert-manager.key'))
    status, = run_cli('-y', '-c', @config, 'init', '--email', 'second@example.org')
    assert_equal 0, status
    assert_equal 'second@example.org', CertManager::Config.new(@config).email
    assert_equal key, File.read(File.join(@dir, 'cert-manager.key'))
  end
end

class ConvertConfigCLITest < Test::Unit::TestCase
  include TestFixtures

  def setup
    @dir = Dir.mktmpdir('cert_manager_convert')
    @v1 = write_config(@dir, 'dns_providers' => {
                         'test_cf' => { 'type' => 'cloudflare', 'api_token' => 'very-secret-token-1234' }
                       })
    @v2 = File.join(@dir, 'config.v2.yml')
  end

  def teardown
    FileUtils.rm_rf(@dir)
  end

  def run_cli(*argv)
    out = StringIO.new
    err = StringIO.new
    old = [$stdout, $stderr, $stdin]
    $stdout = out
    $stderr = err
    $stdin = StringIO.new('')
    [CertManager::CLI.run(argv), out.string, err.string]
  ensure
    $stdout, $stderr, $stdin = old
  end

  def test_converts_and_encrypts_secrets
    status, out, err = run_cli('-c', @v1, 'convert-config')
    assert_equal 0, status, err
    assert_no_match(/very-secret-token-1234/, out)
    assert_no_match(/very-secret-token-1234/, File.read(@v2))
    assert_match(/ENC\[v1:/, File.read(@v2))
    assert_equal 0o600, File.stat(@v2).mode & 0o777
    assert_equal 0o600, File.stat(File.join(@dir, 'cert-manager.key')).mode & 0o777
    config = CertManager::Config.new(@v2)
    assert_equal 'very-secret-token-1234', config.dns_providers['test_cf']['api_token']
  end

  def test_original_file_is_untouched
    before = File.read(@v1)
    run_cli('-c', @v1, 'convert-config')
    assert_equal before, File.read(@v1)
  end

  def test_dry_run_writes_nothing_and_masks_secrets
    status, out, = run_cli('-c', @v1, 'convert-config', '--dry-run')
    assert_equal 0, status
    assert(!(File.exist?(@v2)))
    assert(!(File.exist?(File.join(@dir, 'cert-manager.key'))))
    assert_no_match(/very-secret-token-1234/, out)
    assert_match(/\*\*\*\*1234/, out)
  end

  def test_refuses_to_overwrite_without_confirmation
    File.write(@v2, 'existing')
    status, _, err = run_cli('-c', @v1, 'convert-config')
    assert_equal 1, status
    assert_match(/Aborted/, err)
    assert_equal 'existing', File.read(@v2)
  end

  def test_rejects_already_v2_source
    run_cli('-c', @v1, 'convert-config')
    status, _, err = run_cli('-c', @v2, 'convert-config', '--output', File.join(@dir, 'again.yml'))
    assert_equal 1, status
    assert_match(/already a v2/, err)
  end

  def test_missing_source
    status, _, err = run_cli('-c', File.join(@dir, 'nope.yml'), 'convert-config')
    assert_equal 1, status
    assert_match(/not found/, err)
  end
end
