# frozen_string_literal: true

require 'net/http'
require 'uri'
require 'json'
require_relative 'base'

module CertManager
  module DNSProviders
    # Cloudflare DNS API provider implementation
    # Uses the Cloudflare API v4 to manage DNS TXT records
    #
    # Required credentials:
    #   - api_token: Cloudflare API token with DNS edit permissions
    #
    # Optional credentials:
    #   - zone_id: Pre-configured zone ID (skips zone lookup)
    #
    # @example Configuration
    #   dns_providers:
    #     my_cloudflare:
    #       type: cloudflare
    #       api_token: your-api-token-here
    #
    class Cloudflare < Base
      API_BASE = 'https://api.cloudflare.com/client/v4'

      def self.provider_type
        'cloudflare'
      end

      def self.required_credentials
        ['api_token']
      end

      def initialize(name, credentials)
        super
        @api_token = credentials['api_token']
        @default_zone_id = credentials['zone_id']
        @zone_id_cache = {}
      end

      # Add a TXT record via Cloudflare API
      #
      # @param domain [String] The domain being validated
      # @param record_name [String] Full DNS record name
      # @param value [String] The challenge token value
      # @return [String] The Cloudflare record ID
      def add_txt_record(domain, record_name, value)
        zone_id = get_zone_id(domain)

        uri = URI("#{API_BASE}/zones/#{zone_id}/dns_records")
        request = Net::HTTP::Post.new(uri)
        set_auth_headers(request)
        request['Content-Type'] = 'application/json'

        # TXT record content must be quoted
        quoted_value = value.start_with?('"') ? value : "\"#{value}\""

        request.body = {
          type: 'TXT',
          name: record_name,
          content: quoted_value,
          ttl: 120,
          comment: 'ACME DNS-01 challenge - managed by CertManager'
        }.to_json

        response = make_http_request(uri, request)
        handle_response(response, 'add TXT record')

        data = JSON.parse(response.body)
        data['result']['id']
      end

      # Remove a TXT record via Cloudflare API
      #
      # @param domain [String] The domain that was validated
      # @param record_id [String] The Cloudflare record ID
      # @param _value [String] Unused, for interface compatibility
      # @return [Boolean] True if successful
      def remove_txt_record(domain, record_id, _value = nil)
        zone_id = get_zone_id(domain)

        uri = URI("#{API_BASE}/zones/#{zone_id}/dns_records/#{record_id}")
        request = Net::HTTP::Delete.new(uri)
        set_auth_headers(request)

        response = make_http_request(uri, request)
        handle_response(response, 'remove TXT record')

        true
      end

      # Find existing TXT records matching criteria
      #
      # @param domain [String] The domain to search
      # @param record_name [String] The record name to find
      # @return [Array<Hash>] Matching records with :id and :content
      def find_txt_records(domain, record_name)
        zone_id = get_zone_id(domain)

        uri = URI("#{API_BASE}/zones/#{zone_id}/dns_records")
        uri.query = URI.encode_www_form(type: 'TXT', name: record_name)

        request = Net::HTTP::Get.new(uri)
        set_auth_headers(request)

        response = make_http_request(uri, request)
        handle_response(response, 'find TXT records')

        data = JSON.parse(response.body)
        data['result'].map do |record|
          { id: record['id'], content: record['content'] }
        end
      end

      private

      def set_auth_headers(request)
        request['Authorization'] = "Bearer #{@api_token}"
      end

      def get_zone_id(domain)
        return @default_zone_id if @default_zone_id
        return @zone_id_cache[domain] if @zone_id_cache[domain]

        root_domain = extract_root_domain(domain)

        uri = URI("#{API_BASE}/zones")
        uri.query = URI.encode_www_form(name: root_domain, status: 'active')

        request = Net::HTTP::Get.new(uri)
        set_auth_headers(request)

        response = make_http_request(uri, request)
        handle_response(response, 'get zone ID')

        data = JSON.parse(response.body)

        if data['result'].empty?
          raise DNSProviderError, "Zone not found for domain: #{root_domain}"
        end

        @zone_id_cache[domain] = data['result'][0]['id']
      end

      def handle_response(response, operation)
        return if response.is_a?(Net::HTTPSuccess)

        begin
          data = JSON.parse(response.body)
          errors = data['errors']&.map { |e| e['message'] }&.join(', ') || 'Unknown error'
          raise DNSProviderError, "Cloudflare API failed to #{operation}: #{errors}"
        rescue JSON::ParserError
          raise DNSProviderError, "Cloudflare API failed to #{operation}: HTTP #{response.code}"
        end
      end
    end
  end
end
