# frozen_string_literal: true

require 'net/http'
require 'uri'
require 'json'
require 'openssl'
require 'time'
require_relative 'base'

module CertManager
  module DNSProviders
    # DNS Made Easy API provider implementation
    # Uses the DNS Made Easy REST API v2.0 to manage DNS TXT records
    #
    # Required credentials:
    #   - api_key: DNS Made Easy API key
    #   - secret_key: DNS Made Easy Secret key
    #
    # Optional credentials:
    #   - sandbox: Set to true to use sandbox API (default: false)
    #
    # @example Configuration
    #   dns_providers:
    #     dnsmadeeasy:
    #       type: dnsmadeeasy
    #       api_key: your-api-key
    #       secret_key: your-secret-key
    #
    class DNSMadeEasy < Base
      API_BASE = 'https://api.dnsmadeeasy.com/V2.0'
      SANDBOX_API_BASE = 'https://api.sandbox.dnsmadeeasy.com/V2.0'

      def self.provider_type
        'dnsmadeeasy'
      end

      def self.required_credentials
        %w[api_key secret_key]
      end

      def initialize(name, credentials)
        super
        @api_key = credentials['api_key']
        @secret_key = credentials['secret_key']
        @sandbox = credentials['sandbox'] == true
        @api_base = @sandbox ? SANDBOX_API_BASE : API_BASE
        @domain_id_cache = {}
      end

      # Add a TXT record via DNS Made Easy API
      #
      # @param domain [String] The domain being validated
      # @param record_name [String] Full DNS record name
      # @param value [String] The challenge token value
      # @return [String] The record ID
      def add_txt_record(domain, record_name, value)
        domain_id = get_domain_id(domain)

        # DNS Made Easy wants the record name relative to the domain
        relative_name = extract_relative_name(record_name, domain)

        uri = URI("#{@api_base}/dns/managed/#{domain_id}/records")
        request = Net::HTTP::Post.new(uri)
        set_auth_headers(request)
        request['Content-Type'] = 'application/json'

        request.body = {
          type: 'TXT',
          name: relative_name,
          value: %("#{value}"),
          ttl: 60
        }.to_json

        response = make_http_request(uri, request)
        handle_response(response, 'add TXT record')

        data = JSON.parse(response.body)
        data['id'].to_s
      end

      # Remove a TXT record via DNS Made Easy API
      #
      # @param domain [String] The domain that was validated
      # @param record_id [String] The DNS Made Easy record ID
      # @param _value [String] Unused, for interface compatibility
      # @return [Boolean] True if successful
      def remove_txt_record(domain, record_id, _value = nil)
        domain_id = get_domain_id(domain)

        uri = URI("#{@api_base}/dns/managed/#{domain_id}/records/#{record_id}")
        request = Net::HTTP::Delete.new(uri)
        set_auth_headers(request)

        response = make_http_request(uri, request)

        # 404 is OK - record already deleted
        return true if response.code == '404'

        handle_response(response, 'remove TXT record')
        true
      end

      # Find existing TXT records matching criteria
      #
      # @param domain [String] The domain to search
      # @param record_name [String] The record name to find
      # @return [Array<Hash>] Matching records with :id and :value
      def find_txt_records(domain, record_name)
        domain_id = get_domain_id(domain)
        relative_name = extract_relative_name(record_name, domain)

        uri = URI("#{@api_base}/dns/managed/#{domain_id}/records")
        uri.query = URI.encode_www_form(type: 'TXT', recordName: relative_name)

        request = Net::HTTP::Get.new(uri)
        set_auth_headers(request)

        response = make_http_request(uri, request)
        handle_response(response, 'find TXT records')

        data = JSON.parse(response.body)
        records = data['data'] || []

        records.map do |record|
          { id: record['id'].to_s, value: unquote_txt_value(record['value']) }
        end
      end

      # List all DNS records for a domain
      #
      # @param domain [String] The domain to query
      # @return [Array<Hash>] All DNS records
      def list_records(domain = nil)
        raise ArgumentError, "Domain is required for DNS Made Easy" unless domain

        domain_id = get_domain_id(domain)

        uri = URI("#{@api_base}/dns/managed/#{domain_id}/records")
        request = Net::HTTP::Get.new(uri)
        set_auth_headers(request)

        response = make_http_request(uri, request)
        handle_response(response, 'list records')

        data = JSON.parse(response.body)
        records = data['data'] || []

        records.map do |record|
          {
            'record' => record['name'],
            'type' => record['type'],
            'value' => unquote_txt_value(record['value']),
            'ttl' => record['ttl'],
            'id' => record['id']
          }
        end
      end

      private

      def set_auth_headers(request)
        # DNS Made Easy uses HMAC-SHA1 authentication
        timestamp = Time.now.utc.httpdate
        hmac = OpenSSL::HMAC.hexdigest('SHA1', @secret_key, timestamp)

        request['x-dnsme-apiKey'] = @api_key
        request['x-dnsme-requestDate'] = timestamp
        request['x-dnsme-hmac'] = hmac
      end

      def get_domain_id(domain)
        root = extract_root_domain(domain)
        return @domain_id_cache[root] if @domain_id_cache[root]

        uri = URI("#{@api_base}/dns/managed/name")
        uri.query = URI.encode_www_form(domainname: root)

        request = Net::HTTP::Get.new(uri)
        set_auth_headers(request)

        response = make_http_request(uri, request)
        handle_response(response, 'get domain ID')

        data = JSON.parse(response.body)

        unless data['id']
          raise DNSProviderError, "Domain not found in DNS Made Easy: #{root}"
        end

        @domain_id_cache[root] = data['id']
      end

      def handle_response(response, operation)
        return if response.is_a?(Net::HTTPSuccess)

        begin
          data = JSON.parse(response.body)
          errors = data['error'] || data['errors']&.join(', ') || 'Unknown error'
          raise DNSProviderError, "DNS Made Easy API failed to #{operation}: #{errors}"
        rescue JSON::ParserError
          raise DNSProviderError, "DNS Made Easy API failed to #{operation}: HTTP #{response.code}"
        end
      end
    end
  end
end
