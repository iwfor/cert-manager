# frozen_string_literal: true

require_relative 'test_helper'

class DNSProvidersTest < Test::Unit::TestCase
  def test_registry_includes_all_providers
    expected = %w[cloudflare dreamhost route53 cloud_dns dnsmadeeasy digitalocean linode namecheap]
    expected.each do |type|
      assert CertManager::DNSProviders.registered?(type),
             "Expected '#{type}' to be registered"
    end
  end

  def test_available_types
    types = CertManager::DNSProviders.available_types
    assert types.include?('cloudflare')
    assert types.include?('dreamhost')
  end

  def test_create_raises_for_unknown_type
    assert_raise(ArgumentError) do
      CertManager::DNSProviders.create('unknown_provider', 'test', {})
    end
  end

  def test_create_cloudflare_provider
    provider = CertManager::DNSProviders.create('cloudflare', 'cf', { 'api_token' => 'tok' })
    assert_instance_of CertManager::DNSProviders::Cloudflare, provider
    assert_equal 'cf', provider.name
  end

  def test_create_dreamhost_provider
    provider = CertManager::DNSProviders.create('dreamhost', 'dh', { 'api_key' => 'key' })
    assert_instance_of CertManager::DNSProviders::Dreamhost, provider
  end

  def test_required_credentials_for_cloudflare
    creds = CertManager::DNSProviders.required_credentials('cloudflare')
    assert creds.include?('api_token')
  end

  def test_missing_credentials_raises
    assert_raise(ArgumentError) do
      CertManager::DNSProviders.create('cloudflare', 'cf', {})
    end
  end

  def test_from_config_builds_multiple_providers
    config = {
      'cf1' => { 'type' => 'cloudflare', 'api_token' => 'tok1' },
      'dh1' => { 'type' => 'dreamhost', 'api_key' => 'key1' }
    }
    providers = CertManager::DNSProviders.from_config(config)

    assert_equal 2, providers.length
    assert_instance_of CertManager::DNSProviders::Cloudflare, providers['cf1']
    assert_instance_of CertManager::DNSProviders::Dreamhost, providers['dh1']
  end

  def test_create_digitalocean_provider
    provider = CertManager::DNSProviders.create('digitalocean', 'do', { 'api_token' => 'tok' })
    assert_instance_of CertManager::DNSProviders::DigitalOcean, provider
    assert_equal 'do', provider.name
  end

  def test_create_linode_provider
    provider = CertManager::DNSProviders.create('linode', 'ln', { 'api_token' => 'tok' })
    assert_instance_of CertManager::DNSProviders::Linode, provider
    assert_equal 'ln', provider.name
  end

  def test_create_namecheap_provider
    provider = CertManager::DNSProviders.create('namecheap', 'nc', {
      'api_key' => 'key', 'api_user' => 'user', 'client_ip' => '1.2.3.4'
    })
    assert_instance_of CertManager::DNSProviders::Namecheap, provider
    assert_equal 'nc', provider.name
  end

  def test_missing_credentials_digitalocean
    assert_raise(ArgumentError) do
      CertManager::DNSProviders.create('digitalocean', 'do', {})
    end
  end

  def test_missing_credentials_linode
    assert_raise(ArgumentError) do
      CertManager::DNSProviders.create('linode', 'ln', {})
    end
  end

  def test_missing_credentials_namecheap
    assert_raise(ArgumentError) do
      CertManager::DNSProviders.create('namecheap', 'nc', { 'api_key' => 'key' })
    end
  end

  def test_bracket_accessor
    klass = CertManager::DNSProviders['cloudflare']
    assert_equal CertManager::DNSProviders::Cloudflare, klass
  end

  def test_bracket_accessor_returns_nil_for_unknown
    assert_nil CertManager::DNSProviders['nonexistent']
  end
end
