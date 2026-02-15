# frozen_string_literal: true

require_relative 'test_helper'

class ConfigTest < Test::Unit::TestCase
  include TestFixtures

  def setup
    @tmpdir = Dir.mktmpdir('cert_manager_test')
  end

  def teardown
    FileUtils.rm_rf(@tmpdir)
  end

  def test_loads_valid_config
    path = write_config(@tmpdir)
    config = CertManager::Config.new(path)

    assert_equal 'test@example.com', config.email
    assert_equal 1, config.certificates.length
    assert_equal 'webserver', config.certificates.first['name']
  end

  def test_raises_on_missing_file
    assert_raise(CertManager::ConfigError) do
      CertManager::Config.new('/nonexistent/config.yml')
    end
  end

  def test_defaults
    path = write_config(@tmpdir)
    config = CertManager::Config.new(path)

    assert_equal 'certbot', config.certbot_path
    assert_equal 'INFO', config.log_level
    assert_equal 60, config.propagation_wait
    assert_equal :production, config.default_environment
  end

  def test_cert_dir_is_under_config_dir
    path = write_config(@tmpdir)
    config = CertManager::Config.new(path)

    expected = File.join(config.config_dir, 'live')
    assert_equal expected, config.cert_dir
  end

  def test_rejects_certificate_without_domains
    path = write_config(@tmpdir, 'certificates' => [
      { 'name' => 'bad', 'dns_provider' => 'test_cf' }
    ])
    assert_raise(CertManager::ConfigError) do
      CertManager::Config.new(path)
    end
  end

  def test_rejects_unknown_dns_provider
    path = write_config(@tmpdir, 'certificates' => [
      { 'name' => 'bad', 'domains' => ['x.com'], 'dns_provider' => 'nope' }
    ])
    assert_raise(CertManager::ConfigError) do
      CertManager::Config.new(path)
    end
  end

  def test_rejects_deploy_missing_required_fields
    %w[user host service path].each do |field|
      target = { 'user' => 'u', 'host' => 'h', 'service' => 'nginx', 'path' => '/p' }
      target.delete(field)

      path = write_config(@tmpdir, 'certificates' => [
        { 'name' => 'bad', 'domains' => ['x.com'], 'dns_provider' => 'test_cf',
          'deploy' => [target] }
      ])

      assert_raise(CertManager::ConfigError, "Should reject missing '#{field}'") do
        CertManager::Config.new(path)
      end
    end
  end

  def test_rejects_unsupported_deploy_service
    path = write_config(@tmpdir, 'certificates' => [
      { 'name' => 'bad', 'domains' => ['x.com'], 'dns_provider' => 'test_cf',
        'deploy' => [{ 'user' => 'u', 'host' => 'h', 'path' => '/p', 'service' => 'tomcat' }] }
    ])
    assert_raise(CertManager::ConfigError) do
      CertManager::Config.new(path)
    end
  end

  def test_rejects_unsupported_deploy_action
    path = write_config(@tmpdir, 'certificates' => [
      { 'name' => 'bad', 'domains' => ['x.com'], 'dns_provider' => 'test_cf',
        'deploy' => [{ 'user' => 'u', 'host' => 'h', 'path' => '/p', 'service' => 'nginx', 'action' => 'stop' }] }
    ])
    assert_raise(CertManager::ConfigError) do
      CertManager::Config.new(path)
    end
  end

  def test_accepts_valid_deploy_config
    path = write_config(@tmpdir, 'certificates' => [
      { 'name' => 'ok', 'domains' => ['x.com'], 'dns_provider' => 'test_cf',
        'deploy' => [
          { 'user' => 'deploy', 'host' => 'web1', 'path' => '/etc/ssl/cert.pem',
            'service' => 'nginx', 'action' => 'reload' }
        ] }
    ])
    config = CertManager::Config.new(path)
    assert_equal 1, config.certificates.first['deploy'].length
  end

  def test_accepts_local_deploy_without_user_and_host
    path = write_config(@tmpdir, 'certificates' => [
      { 'name' => 'local', 'domains' => ['x.com'], 'dns_provider' => 'test_cf',
        'deploy' => [
          { 'local' => true, 'path' => '/etc/ssl/cert.pem',
            'service' => 'nginx' }
        ] }
    ])
    config = CertManager::Config.new(path)
    assert_equal 1, config.certificates.first['deploy'].length
  end

  def test_local_deploy_still_requires_service_and_path
    %w[service path].each do |field|
      target = { 'local' => true, 'path' => '/etc/ssl/cert.pem', 'service' => 'nginx' }
      target.delete(field)

      path = write_config(@tmpdir, 'certificates' => [
        { 'name' => 'bad', 'domains' => ['x.com'], 'dns_provider' => 'test_cf',
          'deploy' => [target] }
      ])

      assert_raise(CertManager::ConfigError, "Should reject local target missing '#{field}'") do
        CertManager::Config.new(path)
      end
    end
  end

  def test_remote_deploy_still_requires_user_and_host
    %w[user host].each do |field|
      target = { 'user' => 'u', 'host' => 'h', 'service' => 'nginx', 'path' => '/p' }
      target.delete(field)

      path = write_config(@tmpdir, 'certificates' => [
        { 'name' => 'bad', 'domains' => ['x.com'], 'dns_provider' => 'test_cf',
          'deploy' => [target] }
      ])

      assert_raise(CertManager::ConfigError, "Should reject remote target missing '#{field}'") do
        CertManager::Config.new(path)
      end
    end
  end

  def test_accepts_apache_service
    path = write_config(@tmpdir, 'certificates' => [
      { 'name' => 'ok', 'domains' => ['x.com'], 'dns_provider' => 'test_cf',
        'deploy' => [
          { 'user' => 'deploy', 'host' => 'web1', 'path' => '/etc/ssl/cert.pem',
            'service' => 'apache' }
        ] }
    ])
    config = CertManager::Config.new(path)
    assert_equal 'apache', config.certificates.first['deploy'].first['service']
  end

  def test_accepts_apache_with_service_name
    path = write_config(@tmpdir, 'certificates' => [
      { 'name' => 'ok', 'domains' => ['x.com'], 'dns_provider' => 'test_cf',
        'deploy' => [
          { 'user' => 'deploy', 'host' => 'web1', 'path' => '/etc/ssl/cert.pem',
            'service' => 'apache', 'service_name' => 'httpd' }
        ] }
    ])
    config = CertManager::Config.new(path)
    assert_equal 'httpd', config.certificates.first['deploy'].first['service_name']
  end

  def test_accepts_copy_service
    path = write_config(@tmpdir, 'certificates' => [
      { 'name' => 'ok', 'domains' => ['x.com'], 'dns_provider' => 'test_cf',
        'deploy' => [
          { 'user' => 'deploy', 'host' => 'web1', 'path' => '/etc/ssl/cert.pem',
            'service' => 'copy' }
        ] }
    ])
    config = CertManager::Config.new(path)
    assert_equal 'copy', config.certificates.first['deploy'].first['service']
  end

  def test_accepts_sudo_false
    path = write_config(@tmpdir, 'certificates' => [
      { 'name' => 'ok', 'domains' => ['x.com'], 'dns_provider' => 'test_cf',
        'deploy' => [
          { 'user' => 'deploy', 'host' => 'web1', 'path' => '/etc/ssl/cert.pem',
            'service' => 'nginx', 'sudo' => false }
        ] }
    ])
    config = CertManager::Config.new(path)
    assert_equal false, config.certificates.first['deploy'].first['sudo']
  end

  def test_environment_override
    path = write_config(@tmpdir, 'environment' => 'staging')
    config = CertManager::Config.new(path)
    assert_equal :staging, config.default_environment
  end
end
