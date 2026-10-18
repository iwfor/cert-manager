# frozen_string_literal: true

require_relative 'test_helper'

class ConfigV2Test < Test::Unit::TestCase
  def setup
    @dir = Dir.mktmpdir('cert_manager_v2')
    @path = File.join(@dir, 'config.v2.yml')
    @store = CertManager::SecretStore.new(File.join(@dir, 'cert-manager.key'), create: true)
  end

  def teardown
    FileUtils.rm_rf(@dir)
  end

  def write_v2(overrides = {})
    config = {
      'version' => 2,
      'email' => 'test@example.com',
      'config_dir' => File.join(@dir, 'certbot'),
      'providers' => {
        'cf' => {
          'type' => 'cloudflare',
          'credentials' => { 'api_token' => @store.encrypt('real-token') },
          'zones' => ['example.com', 'Example.NET.']
        },
        'dh' => {
          'type' => 'dreamhost',
          'credentials' => { 'api_key' => @store.encrypt('dh-key') },
          'zones' => ['sub.example.com']
        }
      },
      'certificates' => [
        { 'name' => 'web', 'domains' => ['www.example.com', '*.example.com'] }
      ]
    }.merge(overrides)
    File.write(@path, YAML.dump(config))
    File.chmod(0o600, @path)
    @path
  end

  def load_config
    write_v2 unless File.exist?(@path)
    CertManager::Config.new(@path)
  end

  def test_example_config_is_valid
    FileUtils.cp(File.expand_path('../config.v2.yml.example', __dir__), @path)
    File.chmod(0o600, @path)
    config = nil
    capture_stdout_and_stderr { config = load_config }
    names = config.certificates.to_h { |c| [c['name'], config.provider_name_for(c)] }
    assert_equal 'cloudflare_dns', names['webserver']
    assert_equal 'dreamhost_dns', names['internal-server']
    assert_equal 'dreamhost_dns', names['forced']
  end

  def test_loads_and_decrypts_credentials
    config = load_config
    assert_equal 2, config.version
    assert !config.legacy?
    assert_equal({ 'type' => 'cloudflare', 'api_token' => 'real-token' }, config.dns_providers['cf'])
  end

  def test_provider_resolved_by_zone
    config = load_config
    assert_equal 'cf', config.provider_name_for(config.certificates.first)
  end

  def test_longest_zone_wins
    cert = { 'domains' => ['host.sub.example.com'] }
    assert_equal 'dh', load_config.provider_name_for(cert)
  end

  def test_normalizes_zones
    cert = { 'domains' => ['a.example.net'] }
    assert_equal 'cf', load_config.provider_name_for(cert)
  end

  def test_suffix_match_requires_label_boundary
    write_v2('certificates' => [{ 'name' => 'x', 'domains' => ['notexample.com'] }])
    assert_raise(CertManager::ConfigError) { load_config }
  end

  def test_unmatched_domain_error_lists_zones
    write_v2('certificates' => [{ 'name' => 'x', 'domains' => ['foo.other.org'] }])
    error = assert_raise(CertManager::ConfigError) { load_config }
    assert_match(/foo\.other\.org/, error.message)
    assert_match(/example\.com/, error.message)
  end

  def test_domains_spanning_providers_are_rejected
    write_v2('certificates' => [{ 'name' => 'x', 'domains' => ['a.example.com', 'b.sub.example.com'] }])
    assert_raise(CertManager::ConfigError) { load_config }
  end

  def test_dns_alias_selects_provider
    cert = { 'domains' => ['internal.local'], 'dns_alias' => '_acme-challenge.host.sub.example.com' }
    write_v2('certificates' => [{ 'name' => 'x' }.merge(cert)])
    assert_equal 'dh', load_config.provider_name_for(cert)
  end

  def test_explicit_dns_provider_overrides_zones
    write_v2('certificates' => [{ 'name' => 'x', 'domains' => ['foo.other.org'], 'dns_provider' => 'dh' }])
    assert_equal 'dh', load_config.provider_name_for(load_config.certificates.first)
  end

  def test_unknown_explicit_provider_rejected
    write_v2('certificates' => [{ 'name' => 'x', 'domains' => ['a.example.com'], 'dns_provider' => 'nope' }])
    assert_raise(CertManager::ConfigError) { load_config }
  end

  def test_duplicate_zone_across_providers_rejected
    providers = {
      'a' => { 'type' => 'dreamhost', 'credentials' => { 'api_key' => 'k' }, 'zones' => ['example.com'] },
      'b' => { 'type' => 'dreamhost', 'credentials' => { 'api_key' => 'k' }, 'zones' => ['example.com'] }
    }
    write_v2('providers' => providers, 'certificates' => [])
    error = assert_raise(CertManager::ConfigError) { load_config }
    assert_match(/example\.com/, error.message)
  end

  def test_invalid_zone_rejected
    providers = { 'a' => { 'type' => 'dreamhost', 'credentials' => { 'api_key' => 'k' }, 'zones' => ['not a zone'] } }
    write_v2('providers' => providers, 'certificates' => [])
    assert_raise(CertManager::ConfigError) { load_config }
  end

  def test_provider_without_zones_is_allowed
    providers = { 'a' => { 'type' => 'dreamhost', 'credentials' => { 'api_key' => 'k' } } }
    write_v2('providers' => providers, 'certificates' => [])
    assert_equal ['a'], load_config.dns_providers.keys
  end

  def test_plaintext_secret_is_accepted_with_warning
    providers = { 'a' => { 'type' => 'dreamhost', 'credentials' => { 'api_key' => 'plain' }, 'zones' => ['example.com'] } }
    write_v2('providers' => providers, 'certificates' => [])
    config = nil
    _, err = capture_stdout_and_stderr { config = load_config }
    assert_equal 'plain', config.dns_providers['a']['api_key']
    assert_match(/plaintext/, err)
  end

  def test_missing_key_file_is_a_config_error
    write_v2
    File.delete(File.join(@dir, 'cert-manager.key'))
    error = assert_raise(CertManager::ConfigError) { load_config }
    assert_match(/Key file not found/, error.message)
  end

  def test_insecure_key_file_is_a_config_error
    write_v2
    File.chmod(0o644, File.join(@dir, 'cert-manager.key'))
    assert_raise(CertManager::ConfigError) { load_config }
  end

  def test_unsupported_version_rejected
    write_v2('version' => 3)
    assert_raise(CertManager::ConfigError) { load_config }
  end

  def test_legacy_config_warns_about_deprecation
    legacy = write_config(@dir)
    err = nil
    _, err = capture_stdout_and_stderr { CertManager::Config.new(legacy) }
    assert_match(/DEPRECATED/, err)
    assert_match(/convert-config/, err)
  end

  def test_warn_legacy_can_be_disabled
    legacy = write_config(@dir)
    _, err = capture_stdout_and_stderr { CertManager::Config.new(legacy, warn_legacy: false) }
    assert_no_match(/DEPRECATED/, err)
  end

  def test_resolve_path_precedence
    assert_equal File.expand_path('/x/y.yml'), CertManager::Config.resolve_path('/x/y.yml')
    ENV['CERT_MANAGER_CONFIG'] = '/from/env.yml'
    assert_equal '/from/env.yml', CertManager::Config.resolve_path
    assert_equal '/explicit.yml', CertManager::Config.resolve_path('/explicit.yml')
  ensure
    ENV.delete('CERT_MANAGER_CONFIG')
  end

  def test_normalize_zone
    assert_equal 'example.com', CertManager::Config.normalize_zone(' Example.COM. ')
    assert_raise(CertManager::ConfigError) { CertManager::Config.normalize_zone('localhost') }
  end

  private

  def capture_stdout_and_stderr
    old_out = $stdout
    old_err = $stderr
    $stdout = StringIO.new
    $stderr = StringIO.new
    yield
    [$stdout.string, $stderr.string]
  ensure
    $stdout = old_out
    $stderr = old_err
  end

  include TestFixtures
end
