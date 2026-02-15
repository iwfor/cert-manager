# frozen_string_literal: true

require 'net/http'
require 'uri'
require 'json'
require_relative 'base'

module CertManager
  module DNSProviders
    # Linode (Akamai) DNS API provider implementation
    # Uses the Linode API v4 to manage DNS TXT records
    #
    # Required credentials:
    #   - api_token: Linode personal access token with Domains read/write scope
    #
    # @example Configuration
    #   dns_providers:
    #     linode_dns:
    #       type: linode
    #       api_token: your-api-token-here
    #
    class Linode < Base
      API_BASE = 'https://api.linode.com/v4'

      def self.provider_type
        'linode'
      end

      def self.required_credentials
        ['api_token']
      end

      def initialize(name, credentials)
        super
        @api_token = credentials['api_token']
        @domain_id_cache = {}
      end

      # Add a TXT record via Linode API
      #
      # @param domain [String] The domain being validated
      # @param record_name [String] Full DNS record name
      # @param value [String] The challenge token value
      # @return [String] The Linode record ID
      def add_txt_record(domain, record_name, value)
        domain_id = get_domain_id(domain)
        relative_name = extract_relative_name(record_name, domain)

        uri = URI("#{API_BASE}/domains/#{domain_id}/records")
        request = Net::HTTP::Post.new(uri)
        set_auth_headers(request)
        request['Content-Type'] = 'application/json'

        request.body = {
          type: 'TXT',
          name: relative_name,
          target: value,
          ttl_sec: 120
        }.to_json

        response = make_http_request(uri, request)
        handle_response(response, 'add TXT record')

        data = JSON.parse(response.body)
        data['id'].to_s
      end

      # Remove a TXT record via Linode API
      #
      # @param domain [String] The domain that was validated
      # @param record_id [String] The Linode record ID
      # @param _value [String] Unused, for interface compatibility
      # @return [Boolean] True if successful
      def remove_txt_record(domain, record_id, _value = nil)
        domain_id = get_domain_id(domain)

        uri = URI("#{API_BASE}/domains/#{domain_id}/records/#{record_id}")
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
      # @return [Array<Hash>] Matching records with :id and :target
      def find_txt_records(domain, record_name)
        domain_id = get_domain_id(domain)
        relative_name = extract_relative_name(record_name, domain)

        uri = URI("#{API_BASE}/domains/#{domain_id}/records")
        request = Net::HTTP::Get.new(uri)
        set_auth_headers(request)

        response = make_http_request(uri, request)
        handle_response(response, 'find TXT records')

        data = JSON.parse(response.body)
        records = data['data'] || []

        # Client-side filtering - Linode API doesn't filter by name/type
        records.select do |record|
          record['type'] == 'TXT' && record['name'] == relative_name
        end.map do |record|
          { id: record['id'].to_s, target: record['target'] }
        end
      end

      private

      def set_auth_headers(request)
        request['Authorization'] = "Bearer #{@api_token}"
      end

      def get_domain_id(domain)
        root = extract_root_domain(domain)
        return @domain_id_cache[root] if @domain_id_cache[root]

        uri = URI("#{API_BASE}/domains")
        request = Net::HTTP::Get.new(uri)
        set_auth_headers(request)

        response = make_http_request(uri, request)
        handle_response(response, 'list domains')

        data = JSON.parse(response.body)
        domains = data['data'] || []

        match = domains.find { |d| d['domain'] == root }

        unless match
          raise DNSProviderError, "Domain not found in Linode: #{root}"
        end

        @domain_id_cache[root] = match['id']
      end

      def handle_response(response, operation)
        return if response.is_a?(Net::HTTPSuccess)

        begin
          data = JSON.parse(response.body)
          errors = data['errors']&.map { |e| e['reason'] }&.join(', ') || 'Unknown error'
          raise DNSProviderError, "Linode API failed to #{operation}: #{errors}"
        rescue JSON::ParserError
          raise DNSProviderError, "Linode API failed to #{operation}: HTTP #{response.code}"
        end
      end
    end
  end
end
