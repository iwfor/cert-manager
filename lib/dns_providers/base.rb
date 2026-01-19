# frozen_string_literal: true

module CertManager
  module DNSProviders
    # Abstract base class for DNS providers
    # All DNS provider implementations must inherit from this class
    # and implement the required methods.
    class Base
      attr_reader :name, :credentials

      # @param name [String] Provider instance name from config
      # @param credentials [Hash] Provider-specific credentials
      def initialize(name, credentials)
        @name = name
        @credentials = credentials
        validate_credentials!
      end

      # Add a TXT record for ACME DNS-01 challenge
      #
      # @param domain [String] The domain being validated
      # @param record_name [String] Full DNS record name (e.g., _acme-challenge.example.com)
      # @param value [String] The challenge token value
      # @return [String] Record identifier for later removal
      # @raise [NotImplementedError] If not implemented by subclass
      # @raise [DNSProviderError] If the API call fails
      def add_txt_record(domain, record_name, value)
        raise NotImplementedError, "#{self.class.name} must implement #add_txt_record"
      end

      # Remove a TXT record after challenge completion
      #
      # @param domain [String] The domain that was validated
      # @param record_id [String] Record identifier returned by add_txt_record
      # @param value [String] The challenge token value (needed by some providers)
      # @return [Boolean] True if successful
      # @raise [NotImplementedError] If not implemented by subclass
      # @raise [DNSProviderError] If the API call fails
      def remove_txt_record(domain, record_id, value = nil)
        raise NotImplementedError, "#{self.class.name} must implement #remove_txt_record"
      end

      # Check if a TXT record exists and has propagated
      #
      # @param record_name [String] Full DNS record name
      # @param value [String] Expected value
      # @return [Boolean] True if record exists with correct value
      def record_exists?(record_name, value)
        require 'resolv'
        begin
          records = Resolv::DNS.open do |dns|
            dns.getresources(record_name, Resolv::DNS::Resource::IN::TXT)
          end
          records.any? { |r| r.strings.join == value }
        rescue Resolv::ResolvError
          false
        end
      end

      # Wait for DNS propagation with optional verification
      #
      # @param seconds [Integer] Seconds to wait
      # @param record_name [String, nil] If provided, verify record exists
      # @param value [String, nil] Expected value for verification
      # @return [Boolean] True if propagation confirmed or timeout reached
      def wait_for_propagation(seconds: 60, record_name: nil, value: nil)
        if record_name && value
          wait_with_verification(seconds, record_name, value)
        else
          sleep(seconds)
          true
        end
      end

      # Returns the provider type identifier
      # @return [String] Provider type (e.g., 'cloudflare', 'dreamhost')
      def self.provider_type
        raise NotImplementedError, "#{name} must implement .provider_type"
      end

      # Returns required credential keys for this provider
      # @return [Array<String>] List of required credential keys
      def self.required_credentials
        raise NotImplementedError, "#{name} must implement .required_credentials"
      end

      protected

      # Validate that all required credentials are present
      # @raise [ArgumentError] If required credentials are missing
      def validate_credentials!
        missing = self.class.required_credentials - credentials.keys
        unless missing.empty?
          raise ArgumentError, "Missing required credentials for #{self.class.provider_type}: #{missing.join(', ')}"
        end
      end

      # Make an HTTP request with error handling
      #
      # @param uri [URI] Request URI
      # @param request [Net::HTTP::Request] The request object
      # @param use_ssl [Boolean] Whether to use SSL
      # @return [Net::HTTPResponse] The response
      # @raise [DNSProviderError] If the request fails
      def make_http_request(uri, request, use_ssl: true)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = use_ssl
        http.open_timeout = 10
        http.read_timeout = 30

        response = http.request(request)
        response
      rescue StandardError => e
        raise DNSProviderError, "HTTP request failed: #{e.message}"
      end

      # Extract the root/apex domain from a full domain name
      # Simple implementation - override for more complex TLD handling
      #
      # @param domain [String] Full domain name
      # @return [String] Root domain
      def extract_root_domain(domain)
        parts = domain.split('.')
        # Handle common two-part TLDs (co.uk, com.au, etc.)
        if parts.length > 2 && parts[-2].length <= 3
          parts[-3..-1].join('.')
        elsif parts.length > 2
          parts[-2..-1].join('.')
        else
          domain
        end
      end

      private

      def wait_with_verification(max_seconds, record_name, value)
        interval = 10
        elapsed = 0

        while elapsed < max_seconds
          return true if record_exists?(record_name, value)
          sleep(interval)
          elapsed += interval
        end

        # Final check
        record_exists?(record_name, value)
      end
    end

    # Custom error class for DNS provider errors
    class DNSProviderError < StandardError; end
  end
end
