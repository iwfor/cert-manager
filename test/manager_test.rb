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

  # --- deploy (dry run) append_key ---

  def test_deploy_dry_run_append_key_local
    certs = [
      { 'name' => 'webserver', 'domains' => ['www.example.com'], 'dns_provider' => 'test_cf',
        'deploy' => [
          { 'local' => true, 'path' => '/etc/ssl/combined.pem',
            'append_key' => true, 'service' => 'copy' }
        ] }
    ]
    path = write_config(@tmpdir, 'certificates' => certs)
    manager = build_manager(path, dry_run: true, quiet: false)
    FileUtils.mkdir_p(File.join(@tmpdir, 'certbot'))

    output = capture_output { manager.deploy('webserver') }
    assert_match(/cp fullchain\.pem/, output)
    assert_match(/cat privkey\.pem >> \/etc\/ssl\/combined\.pem/, output)
    assert_match(/chmod 0600 \/etc\/ssl\/combined\.pem/, output)
    assert_no_match(/systemctl/, output)
  end

  def test_deploy_dry_run_append_key_remote
    certs = [
      { 'name' => 'webserver', 'domains' => ['www.example.com'], 'dns_provider' => 'test_cf',
        'deploy' => [
          { 'user' => 'deploy', 'host' => 'lb1', 'path' => '/etc/haproxy/cert.pem',
            'append_key' => true, 'service' => 'copy' }
        ] }
    ]
    path = write_config(@tmpdir, 'certificates' => certs)
    manager = build_manager(path, dry_run: true, quiet: false)
    FileUtils.mkdir_p(File.join(@tmpdir, 'certbot'))

    output = capture_output { manager.deploy('webserver') }
    assert_match(/deploy@lb1/, output)
    assert_match(/cat \/tmp\/privkey.*>> \/etc\/haproxy\/cert\.pem/, output)
    assert_match(/chmod 0600 \/etc\/haproxy\/cert\.pem/, output)
  end

  def test_deploy_dry_run_append_key_with_key_path
    certs = [
      { 'name' => 'webserver', 'domains' => ['www.example.com'], 'dns_provider' => 'test_cf',
        'deploy' => [
          { 'local' => true, 'path' => '/etc/ssl/combined.pem',
            'key_path' => '/etc/ssl/private/key.pem',
            'append_key' => true, 'service' => 'copy' }
        ] }
    ]
    path = write_config(@tmpdir, 'certificates' => certs)
    manager = build_manager(path, dry_run: true, quiet: false)
    FileUtils.mkdir_p(File.join(@tmpdir, 'certbot'))

    output = capture_output { manager.deploy('webserver') }
    assert_match(/cat privkey\.pem >> \/etc\/ssl\/combined\.pem/, output)
    assert_match(/cp privkey\.pem \/etc\/ssl\/private\/key\.pem/, output)
  end

  # --- deploy (dry run) custom_command ---

  def test_deploy_dry_run_custom_command_local
    certs = [
      { 'name' => 'webserver', 'domains' => ['www.example.com'], 'dns_provider' => 'test_cf',
        'deploy' => [
          { 'local' => true, 'path' => '/etc/ssl/cert.pem',
            'service' => 'copy', 'custom_command' => '/usr/local/bin/reload-proxy' }
        ] }
    ]
    path = write_config(@tmpdir, 'certificates' => certs)
    manager = build_manager(path, dry_run: true, quiet: false)
    FileUtils.mkdir_p(File.join(@tmpdir, 'certbot'))

    output = capture_output { manager.deploy('webserver') }
    assert_match(%r{/usr/local/bin/reload-proxy}, output)
    assert_no_match(/systemctl/, output)
  end

  def test_deploy_dry_run_custom_command_remote
    certs = [
      { 'name' => 'webserver', 'domains' => ['www.example.com'], 'dns_provider' => 'test_cf',
        'deploy' => [
          { 'user' => 'deploy', 'host' => 'web1', 'path' => '/etc/ssl/cert.pem',
            'service' => 'copy', 'custom_command' => 'sudo systemctl reload haproxy' }
        ] }
    ]
    path = write_config(@tmpdir, 'certificates' => certs)
    manager = build_manager(path, dry_run: true, quiet: false)
    FileUtils.mkdir_p(File.join(@tmpdir, 'certbot'))

    output = capture_output { manager.deploy('webserver') }
    assert_match(/ssh deploy@web1 sudo systemctl reload haproxy/, output)
    assert_no_match(/\[DRY RUN\]   sudo systemctl/, output)
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

  # --- build_request_cmd (the actual certbot argv) ---
  #
  # Regression coverage for --force not reaching certbot: --force is
  # documented as forcing renewal, but previously only gated cert_manager's
  # own due-date check (in renew) and was never read at all by request, and
  # neither path ever added --force-renewal to the certbot command itself.
  # certbot has its own independent due-date check, so without
  # --force-renewal it refuses ("Certificate not yet due for renewal") even
  # when cert_manager decides to proceed.

  def test_build_request_cmd_omits_force_renewal_by_default
    path = write_config(@tmpdir)
    manager = build_manager(path)
    cert_config = manager.send(:find_certificate, 'webserver')
    provider = manager.instance_variable_get(:@providers)['test_cf']

    cmd = manager.send(:build_request_cmd, ['www.example.com'], provider, nil, cert_config, :production, false)

    assert_false cmd.include?('--force-renewal')
  end

  def test_build_request_cmd_includes_force_renewal_when_forced
    path = write_config(@tmpdir)
    manager = build_manager(path)
    cert_config = manager.send(:find_certificate, 'webserver')
    provider = manager.instance_variable_get(:@providers)['test_cf']

    cmd = manager.send(:build_request_cmd, ['www.example.com'], provider, nil, cert_config, :production, true)

    assert_true cmd.include?('--force-renewal')
  end

  # --- force propagation from request/renew into request_certificate ---
  #
  # Confirms the CLI-facing force: kwarg actually reaches request_certificate
  # (and from there build_request_cmd, covered above) for both commands the
  # --force flag's help text claims to affect.

  def test_request_forwards_force_to_request_certificate
    path = write_config(@tmpdir)
    manager = build_manager(path, dry_run: false)

    captured = nil
    manager.define_singleton_method(:request_certificate) do |cert_config, force: false|
      captured = [cert_config['name'], force]
    end

    manager.request('webserver', force: true)

    assert_equal ['webserver', true], captured
  end

  def test_request_defaults_force_to_false
    path = write_config(@tmpdir)
    manager = build_manager(path, dry_run: false)

    captured = nil
    manager.define_singleton_method(:request_certificate) do |cert_config, force: false|
      captured = [cert_config['name'], force]
    end

    manager.request('webserver')

    assert_equal ['webserver', false], captured
  end

  def test_renew_forwards_force_to_request_certificate
    path = write_config(@tmpdir)
    manager = build_manager(path, dry_run: false)

    captured = []
    manager.define_singleton_method(:request_certificate) do |cert_config, force: false|
      captured << [cert_config['name'], force]
    end

    manager.renew(cert_name: 'webserver', force: true)

    assert_equal [['webserver', true]], captured
  end
  def test_hook_scripts_live_in_a_private_directory
    Dir.mktmpdir do |dir|
      manager = build_manager(write_config(dir))
      path = manager.send(:write_temp_script, 'x.rb', "puts 1\n")
      assert_equal 0o700, File.stat(File.dirname(path)).mode & 0o777
      assert_equal 0o700, File.stat(path).mode & 0o777
      assert_raise(Errno::EEXIST) { manager.send(:write_temp_script, 'x.rb', 'again') }
      manager.send(:remove_hook_dir)
      assert !File.exist?(path)
    end
  end

  def test_cleanup_targets_the_alias_zone_and_strips_wildcards
    Dir.mktmpdir do |dir|
      path = write_config(dir, 'certificates' => [
        { 'name' => 'w', 'domains' => ['*.example.com', 'example.com'], 'dns_provider' => 'test_cf' },
        { 'name' => 'a', 'domains' => ['x.internal.local'], 'dns_provider' => 'test_cf', 'dns_alias' => '_acme-challenge.acme.example.org' }
      ])
      calls = []
      provider = Object.new
      provider.define_singleton_method(:cleanup_challenge_records) { |domain| calls << domain; 0 }
      manager = build_manager(path)
      manager.instance_variable_set(:@providers, { 'test_cf' => provider })
      manager.cleanup('w')
      manager.cleanup('a')
      assert_equal %w[example.com acme.example.org], calls
    end
  end
  def test_generated_hook_scripts_are_valid_ruby_and_use_the_state_dir
    require 'open3'
    Dir.mktmpdir do |dir|
      manager = build_manager(write_config(dir))
      provider = manager.instance_variable_get(:@providers)['test_cf']
      [manager.send(:auth_hook_script, provider, nil), manager.send(:cleanup_hook_script, provider, nil)].each do |script|
        _, err, status = Open3.capture3(RbConfig.ruby, '-c', script)
        assert status.success?, err
        text = File.read(script)
        assert_include text, 'CERT_MANAGER_STATE_DIR'
        assert_no_match(%r{/tmp/certbot_record_}, text)
      end
      manager.send(:remove_hook_dir)
    end
  end
end
