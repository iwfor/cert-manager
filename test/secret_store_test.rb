# frozen_string_literal: true

require_relative 'test_helper'
require_relative '../lib/secret_store'

class SecretStoreTest < Test::Unit::TestCase
  def setup
    @dir = Dir.mktmpdir
    @key_path = File.join(@dir, 'cert-manager.key')
  end

  def teardown
    FileUtils.rm_rf(@dir)
  end

  def store
    CertManager::SecretStore.new(@key_path, create: true)
  end

  def test_creates_key_file_with_owner_only_permissions
    store
    assert_equal 0o600, File.stat(@key_path).mode & 0o777
  end

  def test_round_trip
    s = store
    envelope = s.encrypt('super-secret-token')
    assert s.encrypted?(envelope)
    refute_match(/super-secret/, envelope)
    assert_equal 'super-secret-token', s.decrypt(envelope)
  end

  def test_same_plaintext_encrypts_differently
    s = store
    assert_not_equal s.encrypt('abc'), s.encrypt('abc')
  end

  def test_tampered_value_is_rejected
    s = store
    envelope = s.encrypt('abc')
    tampered = envelope.sub(/.\]\z/, envelope[-2] == 'A' ? 'B]' : 'A]')
    assert_raise(CertManager::SecretStore::Error) { s.decrypt(tampered) }
  end

  def test_wrong_key_is_rejected
    envelope = store.encrypt('abc')
    other = CertManager::SecretStore.new(File.join(@dir, 'other.key'), create: true)
    assert_raise(CertManager::SecretStore::Error) { other.decrypt(envelope) }
  end

  def test_rejects_non_envelope
    assert_raise(CertManager::SecretStore::Error) { store.decrypt('plain') }
  end

  def test_refuses_insecure_key_file
    store
    File.chmod(0o644, @key_path)
    assert_raise(SecurityError) { CertManager::SecretStore.new(@key_path) }
  end

  def test_missing_key_without_create
    assert_raise(CertManager::SecretStore::Error) { CertManager::SecretStore.new(@key_path) }
  end

  def test_generate_key_never_overwrites
    store
    assert_raise(Errno::EEXIST) { CertManager::SecretStore.generate_key(@key_path) }
  end

  def test_key_path_for_config
    assert_equal '/a/b/cert-manager.key', CertManager::SecretStore.key_path_for('/a/b/config.v2.yml')
  end

  def test_mask
    assert_equal '****wxyz', CertManager::SecretStore.mask('abcdefghwxyz')
    assert_equal '****', CertManager::SecretStore.mask('short')
  end

  def test_providers_declare_secret_credentials
    assert_equal ['api_token'], CertManager::DNSProviders['cloudflare'].secret_credentials
    assert_equal [], CertManager::DNSProviders['cloud_dns'].secret_credentials
    CertManager::DNSProviders.available_types.each do |type|
      klass = CertManager::DNSProviders[type]
      assert klass.secret_credentials.is_a?(Array), "#{type} secret_credentials"
    end
  end
end
