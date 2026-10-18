# frozen_string_literal: true

require_relative 'test_helper'

class ProviderCommandsTest < Test::Unit::TestCase
  include TestFixtures

  SECRET = 'cf-super-secret-token-9999'

  def setup
    @dir = Dir.mktmpdir('cert_manager_providers')
    @config = File.join(@dir, 'config.v2.yml')
    run_cli('-c', @config, 'init', '--email', 'me@example.org')
    @original_verify = CertManager::DNSProviders::Cloudflare.instance_method(:verify_credentials)
    @verified = []
    verified = @verified
    CertManager::DNSProviders::Cloudflare.define_method(:verify_credentials) do |zones = []|
      verified << [@api_token, zones]
      raise CertManager::DNSProviders::DNSProviderError, 'Invalid token' if @api_token == 'bad-token'

      true
    end
  end

  def teardown
    CertManager::DNSProviders::Cloudflare.define_method(:verify_credentials, @original_verify)
    FileUtils.rm_rf(@dir)
  end

  def cli(*argv, **kw)
    run_cli('-c', @config, *argv, **kw)
  end

  def raw
    YAML.load_file(@config)
  end

  def add_cloudflare(name = 'cf', *extra)
    cli('add-provider', name, '--type', 'cloudflare', '--key-stdin', *extra, stdin: "#{SECRET}\n")
  end

  def decrypted(name = 'cf')
    CertManager::Config.new(@config).dns_providers.fetch(name)
  end

  def test_add_provider_encrypts_secret
    status, _, err = add_cloudflare('cf', '--zone', 'Example.com')
    assert_equal 0, status, err
    assert_no_match(/#{SECRET}/, File.read(@config))
    assert_match(/ENC\[v1:/, raw['providers']['cf']['credentials']['api_token'])
    assert_equal ['example.com'], raw['providers']['cf']['zones']
    assert_equal SECRET, decrypted['api_token']
    assert_equal 0o600, File.stat(@config).mode & 0o777
  end

  def test_add_provider_verifies_before_saving
    status, _, err = cli('add-provider', 'cf', '--type', 'cloudflare', '--key-stdin', '--zone', 'example.com', stdin: "bad-token\n")
    assert_equal 1, status
    assert_match(/Verification failed: Invalid token/, err)
    assert_equal({}, raw['providers'] || {})
  end

  def test_add_provider_passes_zones_to_verification
    add_cloudflare('cf', '--zone', 'example.com')
    assert_equal [[SECRET, ['example.com']]], @verified
  end

  def test_no_verify_skips_the_api_call
    status, = cli('add-provider', 'cf', '--type', 'cloudflare', '--key-stdin', '--no-verify', stdin: "bad-token\n")
    assert_equal 0, status
    assert_empty @verified
  end

  def test_secret_from_environment
    ENV['TEST_CF_TOKEN'] = SECRET
    status, = cli('add-provider', 'cf', '--type', 'cloudflare', '--key-env', 'TEST_CF_TOKEN')
    assert_equal 0, status
    assert_equal SECRET, decrypted['api_token']
  ensure
    ENV.delete('TEST_CF_TOKEN')
  end

  def test_missing_environment_variable
    status, _, err = cli('add-provider', 'cf', '--type', 'cloudflare', '--key-env', 'DEFINITELY_UNSET_VAR')
    assert_equal 1, status
    assert_match(/DEFINITELY_UNSET_VAR/, err)
  end

  def test_secrets_cannot_be_passed_on_the_command_line
    status, _, err = cli('add-provider', 'cf', '--type', 'cloudflare', '--set', 'api_token=abc')
    assert_equal 2, status
    assert_match(/Secrets cannot be passed with --set/, err)
  end

  def test_non_secret_credentials_via_set
    status, = cli('add-provider', 'cf', '--type', 'cloudflare', '--key-stdin', '--set', 'zone_id=abc123', stdin: "#{SECRET}\n")
    assert_equal 0, status
    assert_equal 'abc123', raw['providers']['cf']['credentials']['zone_id']
  end

  def test_rejects_bad_input
    assert_equal 2, cli('add-provider', 'cf').first
    assert_equal 2, cli('add-provider', 'cf', '--type', 'nonsense').first
    assert_equal 2, cli('add-provider', 'bad name', '--type', 'cloudflare').first
    assert_equal 2, cli('add-provider', 'cf', '--type', 'cloudflare', '--key-stdin', '--key-env', 'X').first
  end

  def test_duplicate_provider
    add_cloudflare
    status, _, err = add_cloudflare
    assert_equal 1, status
    assert_match(/already exists/, err)
  end

  def test_dry_run_changes_nothing
    before = File.read(@config)
    status, out, = add_cloudflare('cf', '--dry-run')
    assert_equal 0, status
    assert_match(/Dry run/, out)
    assert_equal before, File.read(@config)
  end

  def test_update_provider_key
    add_cloudflare
    status, _, err = cli('update-provider-key', 'cf', '--key-stdin', stdin: "new-token-0000\n")
    assert_equal 0, status, err
    assert_equal 'new-token-0000', decrypted['api_token']
    assert_no_match(/new-token-0000/, File.read(@config))
  end

  def test_update_provider_key_verifies_new_key
    add_cloudflare
    status, _, err = cli('update-provider-key', 'cf', '--key-stdin', stdin: "bad-token\n")
    assert_equal 1, status
    assert_match(/Verification failed/, err)
    assert_equal SECRET, decrypted['api_token']
  end

  def test_update_unknown_provider
    status, _, err = cli('update-provider-key', 'nope', '--key-stdin', stdin: "x\n")
    assert_equal 1, status
    assert_match(/Unknown provider 'nope'/, err)
  end

  def test_update_requires_credential_when_provider_has_several_secrets
    cli('add-provider', 'dme', '--type', 'dnsmadeeasy', '--no-verify', '--key-stdin', stdin: "k1\ns1\n")
    status, _, err = cli('update-provider-key', 'dme', '--key-stdin', stdin: "x\n")
    assert_equal 2, status
    assert_match(/--credential/, err)
    status, = cli('update-provider-key', 'dme', '--credential', 'secret_key', '--no-verify', '--key-stdin', stdin: "s2\n")
    assert_equal 0, status
    assert_equal({ 'type' => 'dnsmadeeasy', 'api_key' => 'k1', 'secret_key' => 's2' }, decrypted('dme'))
  end

  def test_add_and_remove_zone
    add_cloudflare
    assert_equal 0, cli('add-zone', 'cf', 'Example.NET.').first
    assert_equal ['example.net'], raw['providers']['cf']['zones']
    assert_equal [[SECRET, ['example.net']]], @verified.last(1)
    assert_equal 0, cli('remove-zone', 'cf', 'example.net').first
    assert_equal [], raw['providers']['cf']['zones']
  end

  def test_zone_cannot_belong_to_two_providers
    add_cloudflare('cf', '--zone', 'example.com')
    cli('add-provider', 'dh', '--type', 'dreamhost', '--no-verify', '--key-stdin', stdin: "k\n")
    status, _, err = cli('add-zone', 'dh', 'example.com')
    assert_equal 1, status
    assert_match(/already served by provider 'cf'/, err)
  end

  def test_remove_missing_zone
    add_cloudflare
    status, _, err = cli('remove-zone', 'cf', 'example.com')
    assert_equal 1, status
    assert_match(/no zone example\.com/, err)
  end

  def test_remove_zone_blocked_by_certificate_unless_forced
    add_cloudflare('cf', '--zone', 'example.com')
    doc = raw.merge('certificates' => [{ 'name' => 'web', 'domains' => ['www.example.com'] }])
    File.write(@config, YAML.dump(doc))
    status, _, err = cli('remove-zone', 'cf', 'example.com')
    assert_equal 1, status
    assert_match(/web/, err)
    assert_equal ['example.com'], raw['providers']['cf']['zones']
    assert_equal 0, cli('remove-zone', 'cf', 'example.com', '--force').first
  end

  def test_remove_provider
    add_cloudflare
    assert_equal 1, cli('remove-provider', 'cf').first # prompt declined on empty stdin
    assert raw['providers'].key?('cf')
    assert_equal 0, cli('remove-provider', 'cf', '--yes').first
    assert_equal({}, raw['providers'])
  end

  def test_remove_provider_blocked_by_explicit_certificate_reference
    add_cloudflare
    File.write(@config, YAML.dump(raw.merge('certificates' => [{ 'name' => 'web', 'domains' => ['a.other.org'], 'dns_provider' => 'cf' }])))
    status, _, err = cli('remove-provider', 'cf', '--yes')
    assert_equal 1, status
    assert_match(/web/, err)
  end

  def test_list_providers_never_prints_secrets
    add_cloudflare('cf', '--zone', 'example.com', '--set', 'zone_id=zid1')
    _, out, = cli('list-providers')
    assert_match(/cf  \(cloudflare\)/, out)
    assert_match(/zones: example\.com/, out)
    assert_match(/api_token: \[encrypted\]/, out)
    assert_match(/zone_id: zid1/, out)
    assert_no_match(/#{SECRET}|ENC\[/, out)
  end

  def test_list_providers_flags_plaintext_secrets
    File.write(@config, YAML.dump(raw.merge('providers' => { 'cf' => { 'type' => 'cloudflare', 'credentials' => { 'api_token' => 'plain' } } })))
    _, out, = cli('list-providers')
    assert_match(/PLAINTEXT/, out)
    assert_no_match(/: plain$/, out)
  end

  def test_single_zone_provider_rejects_second_zone
    cli('add-provider', 'aws', '--type', 'route53', '--set', 'hosted_zone_id=Z1', '--no-verify', '--zone', 'example.com')
    status, _, err = cli('add-zone', 'aws', 'example.org', '--no-verify')
    assert_equal 1, status
    assert_match(/tied to one zone/, err)
  end

  def test_zone_id_only_for_single_zone_providers
    add_cloudflare
    assert_equal 0, cli('add-zone', 'cf', 'example.com', '--zone-id', 'zid9').first
    assert_equal 'zid9', raw['providers']['cf']['credentials']['zone_id']
    cli('add-provider', 'dh', '--type', 'dreamhost', '--no-verify', '--key-stdin', stdin: "k\n")
    status, _, err = cli('add-zone', 'dh', 'example.org', '--zone-id', 'x')
    assert_equal 2, status
    assert_match(/do not take --zone-id/, err)
  end

  def test_refuses_v1_config
    v1 = write_config(@dir)
    status, _, err = run_cli('-c', v1, 'list-providers')
    assert_equal 1, status
    assert_match(/convert-config/, err)
  end

  def test_missing_key_file_does_not_create_a_new_one_when_secrets_exist
    add_cloudflare
    File.delete(File.join(@dir, 'cert-manager.key'))
    status, _, err = cli('update-provider-key', 'cf', '--key-stdin', '--no-verify', stdin: "x\n")
    assert_equal 1, status
    assert_match(/Key file not found/, err)
    assert !File.exist?(File.join(@dir, 'cert-manager.key'))
  end

def test_verify_command_reports_ok_and_exits_zero
  add_cloudflare('cf', '--zone', 'example.com')
  status, out, = cli('verify')
  assert_equal 0, status
  assert_match(/Verifying cf \(cloudflare\)\.\.\. OK/, out)
end

def test_verify_command_fails_when_a_provider_is_rejected
  add_cloudflare('cf', '--zone', 'example.com')
  doc = raw
  doc['providers']['cf']['credentials']['api_token'] = CertManager::SecretStore.new(File.join(@dir, 'cert-manager.key')).encrypt('bad-token')
  File.write(@config, YAML.dump(doc))
  status, out, err = cli('verify')
  assert_equal 1, status
  assert_match(/FAILED: Invalid token/, out)
  assert_match(/1 provider\(s\) failed/, err)
end
  def test_add_zone_that_would_reroute_a_certificate_requires_force
    add_cloudflare('cf', '--zone', 'example.com')
    cli('add-provider', 'dh', '--type', 'dreamhost', '--no-verify', '--key-stdin', stdin: "k\n")
    File.write(@config, YAML.dump(raw.merge('certificates' => [{ 'name' => 'w', 'domains' => ['a.example.com'] }])))
    status, _, err = cli('add-zone', 'dh', 'a.example.com', '--no-verify')
    assert_equal 1, status
    assert_match(/change the DNS provider of certificate\(s\): w/, err)
    assert_equal [], raw['providers']['dh']['zones']
    assert_equal 0, cli('add-zone', 'dh', 'a.example.com', '--no-verify', '--force').first
  end

  def test_unrelated_zone_does_not_need_force
    add_cloudflare('cf', '--zone', 'example.com')
    File.write(@config, YAML.dump(raw.merge('certificates' => [{ 'name' => 'w', 'domains' => ['a.example.com'] }])))
    assert_equal 0, cli('add-zone', 'cf', 'example.net').first
  end

  def test_no_command_output_ever_contains_the_secret
    outputs = []
    outputs << add_cloudflare('cf', '--zone', 'example.com')
    outputs << cli('list-providers')
    outputs << cli('update-provider-key', 'cf', '--key-stdin', '--verbose', stdin: "#{SECRET}\n")
    outputs << cli('add-provider', 'x', '--type', 'cloudflare', '--key-stdin', '--dry-run', '--verbose', stdin: "#{SECRET}\n")
    outputs << cli('verify')
    outputs.flatten.each { |text| assert_no_match(/#{SECRET}|cf-super/, text.to_s) }
  end

  def test_list_providers_hides_all_values_of_unknown_types
    File.write(@config, YAML.dump(raw.merge('providers' => { 'x' => { 'type' => 'mystery', 'credentials' => { 'token' => 'visible-secret' } } })))
    _, out, = cli('list-providers')
    assert_no_match(/visible-secret/, out)
  end

  def test_verification_errors_from_sdks_are_reported_cleanly
    CertManager::DNSProviders::Cloudflare.define_method(:verify_credentials) { |_zones = []| raise IOError, 'sdk exploded' }
    status, _, err = add_cloudflare
    assert_equal 1, status
    assert_match(/Verification failed: sdk exploded/, err)
    assert_equal({}, raw['providers'] || {})
  end
end
