# frozen_string_literal: true

require_relative 'test_helper'

class ManagerTest < Test::Unit::TestCase
  include TestFixtures

  def setup
    @tmpdir = Dir.mktmpdir('cert_manager_test')
  end

  def teardown
    FileUtils.rm_rf(@tmpdir)
  end

  # --- find_certificate / effective_environment ---

  def test_find_certificate_by_name
    path = write_config(@tmpdir)
    manager = build_manager(path)

    cert = manager.send(:find_certificate, 'webserver')
    assert_not_nil cert
    assert_equal 'webserver', cert['name']
  end

  def test_find_certificate_by_domain
    path = write_config(@tmpdir)
    manager = build_manager(path)

    cert = manager.send(:find_certificate, 'www.example.com')
    assert_not_nil cert
  end

  def test_find_certificate_returns_nil_for_unknown
    path = write_config(@tmpdir)
    manager = build_manager(path)

    assert_nil manager.send(:find_certificate, 'nonexistent')
  end

  def test_effective_environment_defaults_to_production
    path = write_config(@tmpdir)
    manager = build_manager(path)

    cert_config = { 'domains' => ['x.com'] }
    assert_equal :production, manager.effective_environment(cert_config)
  end

  def test_effective_environment_respects_cert_level
    path = write_config(@tmpdir)
    manager = build_manager(path)

    cert_config = { 'domains' => ['x.com'], 'environment' => 'staging' }
    assert_equal :staging, manager.effective_environment(cert_config)
  end

  def test_effective_environment_cli_override_wins
    path = write_config(@tmpdir)
    manager = build_manager(path, environment: :staging)

    cert_config = { 'domains' => ['x.com'], 'environment' => 'production' }
    assert_equal :staging, manager.effective_environment(cert_config)
  end

  def test_effective_environment_legacy_staging_flag
    path = write_config(@tmpdir)
    manager = build_manager(path)

    cert_config = { 'domains' => ['x.com'], 'staging' => true }
    assert_equal :staging, manager.effective_environment(cert_config)
  end

  # --- deploy state file ---

  def test_deploy_state_path
    path = write_config(@tmpdir)
    manager = build_manager(path)

    expected = File.join(@tmpdir, 'certbot', 'deploy_state.json')
    assert_equal expected, manager.send(:deploy_state_path)
  end

  def test_load_deploy_state_returns_empty_when_no_file
    path = write_config(@tmpdir)
    manager = build_manager(path)

    state = manager.send(:load_deploy_state)
    assert_equal({ 'pending_deploys' => [] }, state)
  end

  def test_load_deploy_state_handles_corrupt_json
    path = write_config(@tmpdir)
    manager = build_manager(path)

    FileUtils.mkdir_p(File.join(@tmpdir, 'certbot'))
    File.write(manager.send(:deploy_state_path), 'not json{{{')

    state = manager.send(:load_deploy_state)
    assert_equal({ 'pending_deploys' => [] }, state)
  end

  def test_load_deploy_state_handles_empty_file
    path = write_config(@tmpdir)
    manager = build_manager(path)

    FileUtils.mkdir_p(File.join(@tmpdir, 'certbot'))
    File.write(manager.send(:deploy_state_path), '')

    state = manager.send(:load_deploy_state)
    assert_equal({ 'pending_deploys' => [] }, state)
  end

  def test_save_and_load_deploy_state
    path = write_config(@tmpdir)
    manager = build_manager(path)

    FileUtils.mkdir_p(File.join(@tmpdir, 'certbot'))

    state = {
      'pending_deploys' => [
        { 'cert_name' => 'web', 'target' => { 'host' => 'h1' },
          'failed_at' => '2026-01-01T00:00:00Z', 'last_error' => 'timeout' }
      ]
    }
    manager.send(:save_deploy_state, state)

    loaded = manager.send(:load_deploy_state)
    assert_equal 1, loaded['pending_deploys'].length
    assert_equal 'web', loaded['pending_deploys'].first['cert_name']
    assert_equal 'timeout', loaded['pending_deploys'].first['last_error']
  end

  # --- record / clear pending deploys ---

  def test_record_failed_deploy_adds_entry
    path = write_config(@tmpdir)
    manager = build_manager(path)
    FileUtils.mkdir_p(File.join(@tmpdir, 'certbot'))

    target = { 'host' => 'web1', 'user' => 'deploy' }
    manager.send(:record_failed_deploy, 'webserver', target, 'connection refused')

    state = manager.send(:load_deploy_state)
    assert_equal 1, state['pending_deploys'].length

    entry = state['pending_deploys'].first
    assert_equal 'webserver', entry['cert_name']
    assert_equal 'web1', entry['target']['host']
    assert_equal 'connection refused', entry['last_error']
    assert_not_nil entry['failed_at']
  end

  def test_record_failed_deploy_updates_existing_entry
    path = write_config(@tmpdir)
    manager = build_manager(path)
    FileUtils.mkdir_p(File.join(@tmpdir, 'certbot'))

    target = { 'host' => 'web1', 'user' => 'deploy' }
    manager.send(:record_failed_deploy, 'webserver', target, 'first error')
    manager.send(:record_failed_deploy, 'webserver', target, 'second error')

    state = manager.send(:load_deploy_state)
    assert_equal 1, state['pending_deploys'].length
    assert_equal 'second error', state['pending_deploys'].first['last_error']
  end

  def test_record_failed_deploy_tracks_multiple_hosts
    path = write_config(@tmpdir)
    manager = build_manager(path)
    FileUtils.mkdir_p(File.join(@tmpdir, 'certbot'))

    manager.send(:record_failed_deploy, 'webserver', { 'host' => 'web1' }, 'err1')
    manager.send(:record_failed_deploy, 'webserver', { 'host' => 'web2' }, 'err2')

    state = manager.send(:load_deploy_state)
    assert_equal 2, state['pending_deploys'].length
  end

  def test_clear_pending_deploy_removes_entry
    path = write_config(@tmpdir)
    manager = build_manager(path)
    FileUtils.mkdir_p(File.join(@tmpdir, 'certbot'))

    target = { 'host' => 'web1', 'user' => 'deploy' }
    manager.send(:record_failed_deploy, 'webserver', target, 'err')
    manager.send(:clear_pending_deploy, 'webserver', target)

    state = manager.send(:load_deploy_state)
    assert_equal 0, state['pending_deploys'].length
  end

  def test_clear_pending_deploy_only_removes_matching
    path = write_config(@tmpdir)
    manager = build_manager(path)
    FileUtils.mkdir_p(File.join(@tmpdir, 'certbot'))

    manager.send(:record_failed_deploy, 'webserver', { 'host' => 'web1' }, 'err1')
    manager.send(:record_failed_deploy, 'webserver', { 'host' => 'web2' }, 'err2')
    manager.send(:clear_pending_deploy, 'webserver', { 'host' => 'web1' })

    state = manager.send(:load_deploy_state)
    assert_equal 1, state['pending_deploys'].length
    assert_equal 'web2', state['pending_deploys'].first['target']['host']
  end

  # --- deploy (dry run) ---

  def test_deploy_raises_for_unknown_cert
    path = write_config(@tmpdir)
    manager = build_manager(path)

    assert_raise(RuntimeError) { manager.deploy('nonexistent') }
  end

  def test_deploy_raises_when_no_targets
    path = write_config(@tmpdir)
    manager = build_manager(path)

    assert_raise(RuntimeError) { manager.deploy('webserver') }
  end

  def test_deploy_dry_run_does_not_record_failures
    certs = [
      { 'name' => 'webserver', 'domains' => ['www.example.com'], 'dns_provider' => 'test_cf',
        'deploy' => [
          { 'user' => 'deploy', 'host' => 'web1', 'path' => '/etc/ssl/cert.pem',
            'service' => 'nginx' }
        ] }
    ]
    path = write_config(@tmpdir, 'certificates' => certs)
    manager = build_manager(path, dry_run: true)
    FileUtils.mkdir_p(File.join(@tmpdir, 'certbot'))

    manager.deploy('webserver')

    state = manager.send(:load_deploy_state)
    assert_equal 0, state['pending_deploys'].length
  end

  # --- retry_failed_deploys (dry run) ---

  def test_retry_failed_deploys_noop_when_empty
    path = write_config(@tmpdir)
    manager = build_manager(path)
    FileUtils.mkdir_p(File.join(@tmpdir, 'certbot'))

    # Should not raise
    manager.retry_failed_deploys
  end

  def test_retry_failed_deploys_dry_run_preserves_state
    path = write_config(@tmpdir)
    manager = build_manager(path, dry_run: true)
    FileUtils.mkdir_p(File.join(@tmpdir, 'certbot'))

    target = { 'host' => 'web1', 'user' => 'deploy', 'path' => '/etc/ssl/cert.pem',
               'service' => 'nginx' }
    manager.send(:record_failed_deploy, 'webserver', target, 'err')

    manager.retry_failed_deploys

    state = manager.send(:load_deploy_state)
    assert_equal 1, state['pending_deploys'].length
  end

  # --- deploy (dry run) local ---

  def test_deploy_dry_run_local_target
    certs = [
      { 'name' => 'webserver', 'domains' => ['www.example.com'], 'dns_provider' => 'test_cf',
        'deploy' => [
          { 'local' => true, 'path' => '/etc/ssl/cert.pem',
            'key_path' => '/etc/ssl/key.pem', 'service' => 'nginx' }
        ] }
    ]
    path = write_config(@tmpdir, 'certificates' => certs)
    manager = build_manager(path, dry_run: true, quiet: false)
    FileUtils.mkdir_p(File.join(@tmpdir, 'certbot'))

    # Should not raise; dry run logs local commands
    output = capture_output { manager.deploy('webserver') }
    assert_match(/locally/, output)
    assert_match(/sudo cp/, output)
    assert_match(/sudo chmod/, output)
    assert_match(/sudo systemctl reload nginx/, output)
  end

  def test_deploy_dry_run_local_without_sudo
    certs = [
      { 'name' => 'webserver', 'domains' => ['www.example.com'], 'dns_provider' => 'test_cf',
        'deploy' => [
          { 'local' => true, 'path' => '/etc/ssl/cert.pem',
            'service' => 'nginx', 'sudo' => false }
        ] }
    ]
    path = write_config(@tmpdir, 'certificates' => certs)
    manager = build_manager(path, dry_run: true, quiet: false)
    FileUtils.mkdir_p(File.join(@tmpdir, 'certbot'))

    output = capture_output { manager.deploy('webserver') }
    assert_match(/locally/, output)
    assert_no_match(/sudo/, output)
    assert_match(/cp fullchain\.pem/, output)
    assert_match(/systemctl reload nginx/, output)
  end

  def test_deploy_dry_run_remote_without_sudo
    certs = [
      { 'name' => 'webserver', 'domains' => ['www.example.com'], 'dns_provider' => 'test_cf',
        'deploy' => [
          { 'user' => 'deploy', 'host' => 'web1', 'path' => '/etc/ssl/cert.pem',
            'service' => 'nginx', 'sudo' => false }
        ] }
    ]
    path = write_config(@tmpdir, 'certificates' => certs)
    manager = build_manager(path, dry_run: true, quiet: false)
    FileUtils.mkdir_p(File.join(@tmpdir, 'certbot'))

    output = capture_output { manager.deploy('webserver') }
    assert_match(/deploy@web1/, output)
    assert_no_match(/sudo/, output)
  end

  # --- deploy (dry run) copy service ---

  def test_deploy_dry_run_copy_skips_systemctl
    certs = [
      { 'name' => 'webserver', 'domains' => ['www.example.com'], 'dns_provider' => 'test_cf',
        'deploy' => [
          { 'user' => 'deploy', 'host' => 'web1', 'path' => '/etc/ssl/cert.pem',
            'service' => 'copy' }
        ] }
    ]
    path = write_config(@tmpdir, 'certificates' => certs)
    manager = build_manager(path, dry_run: true, quiet: false)
    FileUtils.mkdir_p(File.join(@tmpdir, 'certbot'))

    output = capture_output { manager.deploy('webserver') }
    assert_match(/deploy@web1/, output)
    assert_match(/cp.*fullchain/, output)
    assert_no_match(/systemctl/, output)
  end

  def test_deploy_dry_run_copy_local
    certs = [
      { 'name' => 'webserver', 'domains' => ['www.example.com'], 'dns_provider' => 'test_cf',
        'deploy' => [
          { 'local' => true, 'path' => '/etc/ssl/cert.pem',
            'key_path' => '/etc/ssl/key.pem', 'service' => 'copy' }
        ] }
    ]
    path = write_config(@tmpdir, 'certificates' => certs)
    manager = build_manager(path, dry_run: true, quiet: false)
    FileUtils.mkdir_p(File.join(@tmpdir, 'certbot'))

    output = capture_output { manager.deploy('webserver') }
    assert_match(/locally/, output)
    assert_match(/cp fullchain/, output)
    assert_match(/cp privkey/, output)
    assert_no_match(/systemctl/, output)
  end

  # --- deploy (dry run) apache service ---

  def test_deploy_dry_run_apache_defaults_to_apache2
    certs = [
      { 'name' => 'webserver', 'domains' => ['www.example.com'], 'dns_provider' => 'test_cf',
        'deploy' => [
          { 'user' => 'deploy', 'host' => 'web1', 'path' => '/etc/ssl/cert.pem',
            'service' => 'apache' }
        ] }
    ]
    path = write_config(@tmpdir, 'certificates' => certs)
    manager = build_manager(path, dry_run: true, quiet: false)
    FileUtils.mkdir_p(File.join(@tmpdir, 'certbot'))

    output = capture_output { manager.deploy('webserver') }
    assert_match(/systemctl reload apache2/, output)
  end

  def test_deploy_dry_run_apache_with_httpd_service_name
    certs = [
      { 'name' => 'webserver', 'domains' => ['www.example.com'], 'dns_provider' => 'test_cf',
        'deploy' => [
          { 'user' => 'deploy', 'host' => 'web1', 'path' => '/etc/ssl/cert.pem',
            'service' => 'apache', 'service_name' => 'httpd' }
        ] }
    ]
    path = write_config(@tmpdir, 'certificates' => certs)
    manager = build_manager(path, dry_run: true, quiet: false)
    FileUtils.mkdir_p(File.join(@tmpdir, 'certbot'))

    output = capture_output { manager.deploy('webserver') }
    assert_match(/systemctl reload httpd/, output)
    assert_no_match(/apache2/, output)
  end

  # --- certificate_needs_renewal? ---

  def test_needs_renewal_when_cert_missing
    path = write_config(@tmpdir)
    manager = build_manager(path)

    cert_config = { 'name' => 'webserver', 'domains' => ['www.example.com'] }
    assert_true manager.send(:certificate_needs_renewal?, cert_config)
  end

  # --- renew ---

  def test_renew_raises_for_unknown_cert
    path = write_config(@tmpdir)
    manager = build_manager(path)
    FileUtils.mkdir_p(File.join(@tmpdir, 'certbot'))

    assert_raise(RuntimeError) { manager.renew(cert_name: 'nonexistent') }
  end
end
