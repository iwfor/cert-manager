# frozen_string_literal: true

# DNS Providers module - Registry and factory for DNS provider implementations
#
# This module provides automatic registration and instantiation of DNS providers.
# New providers can be added by creating a class that inherits from Base and
# implements the required methods.
#
# @example Adding a new provider
#   # Create lib/dns_providers/my_provider.rb
#   module CertManager
#     module DNSProviders
#       class MyProvider < Base
#         def self.provider_type
#           'my_provider'
#         end
#
#         def self.required_credentials
#           ['api_key']
#         end
#
#         # ... implement add_txt_record, remove_txt_record
#       end
#     end
#   end
#
# @example Using the registry
#   provider = CertManager::DNSProviders.create('cloudflare', 'my_cf', {
#     'api_token' => 'xxx'
#   })
#   provider.add_txt_record('example.com', '_acme-challenge.example.com', 'token')

require_relative 'dns_providers/base'
require_relative 'dns_providers/cloudflare'
require_relative 'dns_providers/dreamhost'
require_relative 'dns_providers/route53'
require_relative 'dns_providers/cloud_dns'
require_relative 'dns_providers/dnsmadeeasy'

module CertManager
  module DNSProviders
    class << self
      # Registry of provider types to classes
      def registry
        @registry ||= {}
      end

      # Register a provider class
      #
      # @param provider_class [Class] A class inheriting from Base
      def register(provider_class)
        unless provider_class < Base
          raise ArgumentError, "Provider must inherit from DNSProviders::Base"
        end

        registry[provider_class.provider_type] = provider_class
      end

      # Create a provider instance by type
      #
      # @param type [String] The provider type (e.g., 'cloudflare', 'dreamhost')
      # @param name [String] Instance name for this provider
      # @param credentials [Hash] Provider credentials
      # @return [Base] Provider instance
      # @raise [ArgumentError] If provider type is unknown
      def create(type, name, credentials)
        provider_class = registry[type]

        unless provider_class
          available = registry.keys.join(', ')
          raise ArgumentError, "Unknown DNS provider type: '#{type}'. Available: #{available}"
        end

        provider_class.new(name, credentials)
      end

      # List all registered provider types
      #
      # @return [Array<String>] Registered provider types
      def available_types
        registry.keys
      end

      # Get provider class by type
      #
      # @param type [String] The provider type
      # @return [Class, nil] The provider class or nil
      def [](type)
        registry[type]
      end

      # Check if a provider type is registered
      #
      # @param type [String] The provider type
      # @return [Boolean]
      def registered?(type)
        registry.key?(type)
      end

      # Get required credentials for a provider type
      #
      # @param type [String] The provider type
      # @return [Array<String>] Required credential keys
      # @raise [ArgumentError] If provider type is unknown
      def required_credentials(type)
        provider_class = registry[type]
        raise ArgumentError, "Unknown provider type: #{type}" unless provider_class

        provider_class.required_credentials
      end

      # Create multiple providers from configuration hash
      #
      # @param config [Hash] Configuration hash with provider definitions
      # @return [Hash<String, Base>] Hash of provider name to instance
      #
      # @example
      #   config = {
      #     'cloudflare_main' => { 'type' => 'cloudflare', 'api_token' => 'xxx' },
      #     'dreamhost_backup' => { 'type' => 'dreamhost', 'api_key' => 'yyy' }
      #   }
      #   providers = DNSProviders.from_config(config)
      def from_config(config)
        providers = {}

        config.each do |name, provider_config|
          type = provider_config['type']
          credentials = provider_config.reject { |k, _| k == 'type' }

          providers[name] = create(type, name, credentials)
        end

        providers
      end
    end

    # Auto-register built-in providers
    register(Cloudflare)
    register(Dreamhost)
    register(Route53)
    register(CloudDNS)
    register(DNSMadeEasy)
  end
end
