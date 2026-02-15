# frozen_string_literal: true

require 'net/http'
require 'uri'
require 'json'
require_relative 'base'

module CertManager
  module DNSProviders
    # DigitalOcean DNS API provider implementation
    # Uses the DigitalOcean API v2 to manage DNS TXT records
    #
    # Required credentials:
    #   - api_token: DigitalOcean personal access token with read/write scope
    #
    # @example Configuration
    #   dns_providers:
    #     digitalocean_dns:
    #       type: digitalocean
    #       api_token: your-api-token-here
    #
    class DigitalOcean < Base
      API_BASE = 'https://api.digitalocean.com/v2'

      def self.provider_type
        'digitalocean'
      end

      def self.required_credentials
        ['api_token']
      end

      def initialize(name, credentials)
        super
        @api_token = credentials['api_token']
      end

      # Add a TXT record via DigitalOcean API
      #
      # @param domain [String] The domain being validated
      # @param record_name [String] Full DNS record name
      # @param value [String] The challenge token value
      # @return [String] The DigitalOcean record ID
      def add_txt_record(domain, record_name, value)
        root = extract_root_domain(domain)
        relative_name = extract_relative_name(record_name, domain)

        uri = URI("#{API_BASE}/domains/#{root}/records")
        request = Net::HTTP::Post.new(uri)
        set_auth_headers(request)
        request['Content-Type'] = 'application/json'

        request.body = {
          type: 'TXT',
          name: relative_name,
          data: value,
          ttl: 120
        }.to_json

        response = make_http_request(uri, request)
        handle_response(response, 'add TXT record')

        data = JSON.parse(response.body)
        data['domain_record']['id'].to_s
      end

      # Remove a TXT record via DigitalOcean API
      #
      # @param domain [String] The domain that was validated
      # @param record_id [String] The DigitalOcean record ID
      # @param _value [String] Unused, for interface compatibility
      # @return [Boolean] True if successful
      def remove_txt_record(domain, record_id, _value = nil)
        root = extract_root_domain(domain)

        uri = URI("#{API_BASE}/domains/#{root}/records/#{record_id}")
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
      # @return [Array<Hash>] Matching records with :id and :data
      def find_txt_records(domain, record_name)
        root = extract_root_domain(domain)
        relative_name = extract_relative_name(record_name, domain)

        uri = URI("#{API_BASE}/domains/#{root}/records")
        uri.query = URI.encode_www_form(type: 'TXT', name: relative_name)

        request = Net::HTTP::Get.new(uri)
        set_auth_headers(request)

        response = make_http_request(uri, request)
        handle_response(response, 'find TXT records')

        data = JSON.parse(response.body)
        records = data['domain_records'] || []

        records.map do |record|
          { id: record['id'].to_s, data: record['data'] }
        end
      end

      private

      def set_auth_headers(request)
        request['Authorization'] = "Bearer #{@api_token}"
      end

      def handle_response(response, operation)
        return if response.is_a?(Net::HTTPSuccess)

        begin
          data = JSON.parse(response.body)
          message = data['message'] || data['id'] || 'Unknown error'
          raise DNSProviderError, "DigitalOcean API failed to #{operation}: #{message}"
        rescue JSON::ParserError
          raise DNSProviderError, "DigitalOcean API failed to #{operation}: HTTP #{response.code}"
        end
      end
    end
  end
end
