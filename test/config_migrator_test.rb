# frozen_string_literal: true

require_relative 'test_helper'
require_relative '../lib/config_migrator'

class ConfigMigratorTest < Test::Unit::TestCase
  def v1(overrides = {})
    {
      'email' => 'a@example.com',
      'log_level' => 'DEBUG',
      'dns_providers' => {
        'cf' => { 'type' => 'cloudflare', 'api_token' => 'cf-secret-token', 'zone_id' => 'abc123' },
        'dh' => { 'type' => 'dreamhost', 'api_key' => 'dh-secret-key' }
      },
      'certificates' => [
        { 'name' => 'web', 'domains' => ['www.example.com', '*.example.com'], 'dns_provider' => 'cf',
          'deploy' => [{ 'local' => true, 'service' => 'nginx', 'path' => '/etc/x.crt' }] },
        { 'name' => 'other', 'domains' => ['host.example.org'], 'dns_provider' => 'dh' }
      ]
    }.merge(overrides)
  end

  def migrate(doc = v1)
    CertManager::ConfigMigrator.new(doc, encryptor: ->(value) { "ENC<#{value}>" }).migrate
  end

  def test_document_is_v2_with_settings_copied
    doc = migrate.document
    assert_equal 2, doc['version']
    assert_equal 'a@example.com', doc['email']
    assert_equal 'DEBUG', doc['log_level']
    assert(!(doc.key?('dns_providers')))
  end

  def test_secrets_are_encrypted_and_others_left_plain
    providers = migrate.document['providers']
    assert_equal 'ENC<cf-secret-token>', providers['cf']['credentials']['api_token']
    assert_equal 'abc123', providers['cf']['credentials']['zone_id']
    assert_equal 'ENC<dh-secret-key>', providers['dh']['credentials']['api_key']
    assert_equal %w[cf.api_token dh.api_key], migrate.encrypted
  end

  def test_zones_inferred_from_certificates
    result = migrate
    assert_equal({ 'cf' => ['example.com'], 'dh' => ['example.org'] }, result.zones)
  end

  def test_dns_provider_dropped_when_zones_route_correctly
    certs = migrate.document['certificates']
    assert(!(certs.any? { |c| c.key?('dns_provider') }))
    assert_equal [{ 'local' => true, 'service' => 'nginx', 'path' => '/etc/x.crt' }], certs.first['deploy']
  end

  def test_shared_root_keeps_explicit_provider_on_the_loser
    doc = v1
    doc['certificates'] << { 'name' => 'third', 'domains' => ['x.example.com'], 'dns_provider' => 'dh' }
    result = migrate(doc)
    assert_equal ['third'], result.explicit_certs
    third = result.document['certificates'].last
    assert_equal 'dh', third['dns_provider']
  end

  def test_provider_without_certificates_gets_warning
    doc = v1('certificates' => [])
    result = migrate(doc)
    assert_equal({ 'cf' => [], 'dh' => [] }, result.zones)
    assert_equal 2, result.warnings.size
  end

  def test_unknown_provider_type_has_every_credential_encrypted
    doc = v1('dns_providers' => { 'x' => { 'type' => 'mystery', 'token' => 't' } }, 'certificates' => [])
    result = migrate(doc)
    assert_equal 'ENC<t>', result.document['providers']['x']['credentials']['token']
    assert(result.warnings.any? { |w| w.include?('unknown type') })
  end

  def test_alias_zone_is_used_for_routing
    doc = v1('certificates' => [
               { 'name' => 'int', 'domains' => ['server.internal.local'], 'dns_provider' => 'dh',
                 'dns_alias' => '_acme-challenge.acme.example.org' }
             ])
    assert_equal ['example.org'], migrate(doc).zones['dh']
  end

  def test_unknown_provider_reference_is_rejected
    doc = v1('certificates' => [{ 'name' => 'x', 'domains' => ['a.example.com'], 'dns_provider' => 'nope' }])
    assert_raise(CertManager::ConfigError) { migrate(doc) }
  end

  def test_result_loads_as_valid_v2_config
    Dir.mktmpdir do |dir|
      store = CertManager::SecretStore.new(File.join(dir, 'cert-manager.key'), create: true)
      result = CertManager::ConfigMigrator.new(v1, encryptor: store.method(:encrypt)).migrate
      path = File.join(dir, 'config.v2.yml')
      File.write(path, YAML.dump(result.document))
      File.chmod(0o600, path)
      config = CertManager::Config.new(path)
      assert_equal 'cf-secret-token', config.dns_providers['cf']['api_token']
      assert_equal 'cf', config.provider_name_for(config.certificates.first)
      assert_equal 'dh', config.provider_name_for(config.certificates.last)
    end
  end
  def test_unusable_zone_keeps_explicit_provider_with_warning
    doc = v1('certificates' => [{ 'name' => 'intra', 'domains' => ['intranet'], 'dns_provider' => 'cf' }])
    result = migrate(doc)
    assert_equal({ 'cf' => [], 'dh' => [] }, result.zones)
    assert_equal 'cf', result.document['certificates'].first['dns_provider']
    assert(result.warnings.any? { |w| w.include?("'intranet'") })
  end

  def test_single_zone_provider_gets_only_one_zone
    doc = v1('dns_providers' => { 'aws' => { 'type' => 'route53', 'hosted_zone_id' => 'Z1' } },
             'certificates' => [{ 'name' => 'a', 'domains' => ['a.example.com'], 'dns_provider' => 'aws' },
                                { 'name' => 'b', 'domains' => ['b.example.org'], 'dns_provider' => 'aws' }])
    result = migrate(doc)
    assert_equal({ 'aws' => ['example.com'] }, result.zones)
    assert_equal ['b'], result.explicit_certs
  end
end
