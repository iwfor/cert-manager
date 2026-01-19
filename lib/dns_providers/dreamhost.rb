# frozen_string_literal: true

require 'net/http'
require 'uri'
require 'json'
require_relative 'base'

module CertManager
  module DNSProviders
    # Dreamhost DNS API provider implementation
    # Uses the Dreamhost API to manage DNS TXT records
    #
    # Required credentials:
    #   - api_key: Dreamhost API key with dns-* permissions
    #
    # Note: Dreamhost API doesn't return record IDs, so removal requires
    # the original record name and value.
    #
    # @example Configuration
    #   dns_providers:
    #     my_dreamhost:
    #       type: dreamhost
    #       api_key: your-api-key-here
    #
    class Dreamhost < Base
      API_BASE = 'https://api.dreamhost.com'

      def self.provider_type
        'dreamhost'
      end

      def self.required_credentials
        ['api_key']
      end

      def initialize(name, credentials)
        super
        @api_key = credentials['api_key']
      end

      # Add a TXT record via Dreamhost API
      #
      # @param domain [String] The domain being validated (unused, for interface)
      # @param record_name [String] Full DNS record name
      # @param value [String] The challenge token value
      # @return [Hash] Record identifier containing name and value for removal
      def add_txt_record(domain, record_name, value)
        params = {
          key: @api_key,
          cmd: 'dns-add_record',
          record: record_name,
          type: 'TXT',
          value: value,
          comment: 'ACME DNS-01 challenge',
          format: 'json'
        }

        response = make_api_request(params)
        data = parse_response(response)

        if data['result'] != 'success'
          raise DNSProviderError, "Dreamhost API failed to add TXT record: #{data['data']}"
        end

        # Dreamhost doesn't return an ID, return composite identifier
        { record_name: record_name, value: value }.to_json
      end

      # Remove a TXT record via Dreamhost API
      #
      # @param domain [String] The domain (unused, for interface)
      # @param record_id [String] JSON string with record_name and value
      # @param value [String] The challenge value (used if record_id doesn't contain it)
      # @return [Boolean] True if successful
      def remove_txt_record(domain, record_id, value = nil)
        # Parse the record identifier
        record_info = parse_record_id(record_id, value)

        params = {
          key: @api_key,
          cmd: 'dns-remove_record',
          record: record_info[:record_name],
          type: 'TXT',
          value: record_info[:value],
          format: 'json'
        }

        response = make_api_request(params)
        data = parse_response(response)

        if data['result'] != 'success'
          # Ignore "record not found" errors during cleanup
          unless data['data'].to_s.include?('no such record')
            raise DNSProviderError, "Dreamhost API failed to remove TXT record: #{data['data']}"
          end
        end

        true
      end

      # List all DNS records for a domain
      #
      # @param domain [String] The domain to query
      # @return [Array<Hash>] All DNS records
      def list_records(domain = nil)
        params = {
          key: @api_key,
          cmd: 'dns-list_records',
          format: 'json'
        }

        response = make_api_request(params)
        data = parse_response(response)

        if data['result'] != 'success'
          raise DNSProviderError, "Dreamhost API failed to list records: #{data['data']}"
        end

        records = data['data'] || []

        # Filter by domain if specified
        if domain
          root = extract_root_domain(domain)
          records = records.select { |r| r['record'].end_with?(root) }
        end

        records
      end

      # Find existing TXT records matching criteria
      #
      # @param domain [String] The domain to search
      # @param record_name [String] The record name to find
      # @return [Array<Hash>] Matching records
      def find_txt_records(domain, record_name)
        all_records = list_records(domain)

        all_records.select do |record|
          record['type'] == 'TXT' && record['record'] == record_name
        end.map do |record|
          { record_name: record['record'], value: record['value'] }
        end
      end

      # Remove all ACME challenge records for a domain
      #
      # @param domain [String] The domain to clean up
      # @return [Integer] Number of records removed
      def cleanup_challenge_records(domain)
        record_name = "_acme-challenge.#{domain}"
        records = find_txt_records(domain, record_name)

        records.each do |record|
          record_id = { record_name: record[:record_name], value: record[:value] }.to_json
          remove_txt_record(domain, record_id)
        end

        records.length
      end

      # Override propagation wait - Dreamhost can be slower
      def wait_for_propagation(seconds: 120, record_name: nil, value: nil)
        super(seconds: seconds, record_name: record_name, value: value)
      end

      private

      def make_api_request(params)
        uri = URI(API_BASE)
        uri.query = URI.encode_www_form(params)

        request = Net::HTTP::Get.new(uri)
        make_http_request(uri, request)
      end

      def parse_response(response)
        unless response.is_a?(Net::HTTPSuccess)
          raise DNSProviderError, "Dreamhost API HTTP error: #{response.code}"
        end

        JSON.parse(response.body)
      rescue JSON::ParserError => e
        raise DNSProviderError, "Dreamhost API returned invalid JSON: #{e.message}"
      end

      def parse_record_id(record_id, fallback_value)
        # Try to parse as JSON first
        begin
          info = JSON.parse(record_id)
          {
            record_name: info['record_name'],
            value: info['value']
          }
        rescue JSON::ParserError
          # Assume record_id is the record name
          {
            record_name: record_id,
            value: fallback_value
          }
        end
      end
    end
  end
end
