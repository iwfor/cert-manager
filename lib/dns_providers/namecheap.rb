# frozen_string_literal: true

require 'net/http'
require 'uri'
require 'rexml/document'
require_relative 'base'

module CertManager
  module DNSProviders
    # Namecheap DNS API provider implementation
    # Uses the Namecheap XML API to manage DNS TXT records
    #
    # Required credentials:
    #   - api_key: Namecheap API key
    #   - api_user: Namecheap API username
    #   - client_ip: Whitelisted IP address for API access
    #
    # Note: Namecheap has no individual record CRUD — all operations use a
    # read-modify-write pattern: get all host records, modify the list, then
    # set all host records at once.
    #
    # @example Configuration
    #   dns_providers:
    #     namecheap_dns:
    #       type: namecheap
    #       api_key: your-api-key
    #       api_user: your-username
    #       client_ip: 1.2.3.4
    #
    class Namecheap < Base
      API_BASE = 'https://api.namecheap.com/xml.response'

      def self.provider_type
        'namecheap'
      end

      def self.required_credentials
        %w[api_key api_user client_ip]
      end

      def initialize(name, credentials)
        super
        @api_key = credentials['api_key']
        @api_user = credentials['api_user']
        @client_ip = credentials['client_ip']
      end

      # Add a TXT record via Namecheap API (read-modify-write)
      #
      # @param domain [String] The domain being validated
      # @param record_name [String] Full DNS record name
      # @param value [String] The challenge token value
      # @return [String] The TXT value (used as record identifier)
      def add_txt_record(domain, record_name, value)
        root = extract_root_domain(domain)
        sld, tld = split_domain(root)
        relative_name = extract_relative_name(record_name, domain)

        # Get existing records
        hosts = get_hosts(sld, tld)

        # Add the new TXT record
        hosts << {
          'HostName' => relative_name,
          'RecordType' => 'TXT',
          'Address' => value,
          'TTL' => '120'
        }

        # Write all records back
        set_hosts(sld, tld, hosts)

        # Return the value as the record identifier (no real IDs from Namecheap)
        value
      end

      # Remove a TXT record via Namecheap API (read-modify-write)
      #
      # @param domain [String] The domain that was validated
      # @param record_id [String] The TXT value to remove
      # @param value [String] The challenge value (used if record_id is nil)
      # @return [Boolean] True if successful
      def remove_txt_record(domain, record_id, value = nil)
        target_value = record_id || value
        root = extract_root_domain(domain)
        sld, tld = split_domain(root)

        # Get existing records
        hosts = get_hosts(sld, tld)

        # Remove the matching TXT record by value
        hosts.reject! do |host|
          host['RecordType'] == 'TXT' && host['Address'] == target_value
        end

        # Write remaining records back
        set_hosts(sld, tld, hosts)

        true
      end

      # Find existing TXT records matching criteria
      #
      # @param domain [String] The domain to search
      # @param record_name [String] The record name to find
      # @return [Array<Hash>] Matching records with :name and :value
      def find_txt_records(domain, record_name)
        root = extract_root_domain(domain)
        sld, tld = split_domain(root)
        relative_name = extract_relative_name(record_name, domain)

        hosts = get_hosts(sld, tld)

        hosts.select do |host|
          host['RecordType'] == 'TXT' && host['HostName'] == relative_name
        end.map do |host|
          { name: host['HostName'], value: host['Address'] }
        end
      end

      private

      # Split a root domain into SLD and TLD for Namecheap API params
      # e.g., "example.com" → ["example", "com"]
      #        "example.co.uk" → ["example", "co.uk"]
      def split_domain(root_domain)
        parts = root_domain.split('.')
        if parts.length > 2 && parts[-2].length <= 3
          [parts[0..-3].join('.'), parts[-2..].join('.')]
        else
          [parts[0..-2].join('.'), parts[-1]]
        end
      end

      def base_params
        {
          'ApiUser' => @api_user,
          'ApiKey' => @api_key,
          'UserName' => @api_user,
          'ClientIp' => @client_ip
        }
      end

      # Fetch all host records for a domain
      def get_hosts(sld, tld)
        params = base_params.merge(
          'Command' => 'namecheap.domains.dns.getHosts',
          'SLD' => sld,
          'TLD' => tld
        )

        uri = URI(API_BASE)
        uri.query = URI.encode_www_form(params)
        request = Net::HTTP::Get.new(uri)

        response = make_http_request(uri, request)
        handle_xml_response(response, 'get host records')

        parse_hosts(response.body)
      end

      # Set all host records for a domain (overwrites existing)
      def set_hosts(sld, tld, hosts)
        params = base_params.merge(
          'Command' => 'namecheap.domains.dns.setHosts',
          'SLD' => sld,
          'TLD' => tld
        )

        # Add each host record as numbered parameters
        hosts.each_with_index do |host, i|
          n = i + 1
          params["HostName#{n}"] = host['HostName']
          params["RecordType#{n}"] = host['RecordType']
          params["Address#{n}"] = host['Address']
          params["TTL#{n}"] = host['TTL'] || '1800'
          params["MXPref#{n}"] = host['MXPref'] || '10'
        end

        uri = URI(API_BASE)
        uri.query = URI.encode_www_form(params)
        request = Net::HTTP::Get.new(uri)

        response = make_http_request(uri, request)
        handle_xml_response(response, 'set host records')
      end

      # Parse the XML response from getHosts into an array of host hashes
      def parse_hosts(xml_body)
        doc = REXML::Document.new(xml_body)
        hosts = []

        doc.elements.each('//host') do |host|
          hosts << {
            'HostName' => host.attributes['Name'],
            'RecordType' => host.attributes['Type'],
            'Address' => host.attributes['Address'],
            'TTL' => host.attributes['TTL'],
            'MXPref' => host.attributes['MXPref']
          }
        end

        hosts
      end

      def handle_xml_response(response, operation)
        unless response.is_a?(Net::HTTPSuccess)
          raise DNSProviderError, "Namecheap API failed to #{operation}: HTTP #{response.code}"
        end

        doc = REXML::Document.new(response.body)
        status = doc.root&.attributes&.[]('Status')

        return if status == 'OK'

        errors = []
        doc.elements.each('//Error') do |err|
          errors << err.text
        end
        error_msg = errors.empty? ? 'Unknown error' : errors.join(', ')
        raise DNSProviderError, "Namecheap API failed to #{operation}: #{error_msg}"
      end
    end
  end
end
