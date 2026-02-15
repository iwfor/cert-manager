# frozen_string_literal: true

require_relative 'base'

module CertManager
  module DNSProviders
    # AWS Route 53 DNS provider implementation
    # Uses the AWS SDK to manage DNS TXT records
    #
    # Required credentials:
    #   - hosted_zone_id: The Route 53 hosted zone ID
    #
    # Optional credentials (uses AWS credential chain if not provided):
    #   - access_key_id: AWS access key ID
    #   - secret_access_key: AWS secret access key
    #   - region: AWS region (defaults to us-east-1)
    #   - session_token: AWS session token (for temporary credentials)
    #
    # The provider will use the standard AWS credential chain if access keys
    # are not provided:
    #   1. Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    #   2. Shared credentials file (~/.aws/credentials)
    #   3. IAM role (if running on EC2/ECS/Lambda)
    #
    # @example Configuration with explicit credentials
    #   dns_providers:
    #     route53_main:
    #       type: route53
    #       hosted_zone_id: Z1234567890ABC
    #       access_key_id: AKIAIOSFODNN7EXAMPLE
    #       secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
    #
    # @example Configuration using AWS credential chain
    #   dns_providers:
    #     route53_main:
    #       type: route53
    #       hosted_zone_id: Z1234567890ABC
    #
    class Route53 < Base
      def self.provider_type
        'route53'
      end

      def self.required_credentials
        ['hosted_zone_id']
      end

      def initialize(name, credentials)
        super
        @hosted_zone_id = credentials['hosted_zone_id']
        @region = credentials['region'] || 'us-east-1'

        # Initialize AWS client
        @client = create_client(credentials)
      end

      # Add a TXT record via Route 53
      #
      # @param domain [String] The domain being validated
      # @param record_name [String] Full DNS record name
      # @param value [String] The challenge token value
      # @return [String] The record name (used as identifier for removal)
      def add_txt_record(domain, record_name, value)
        fqdn = ensure_fqdn(record_name)

        # TXT records need to be quoted
        quoted_value = %("#{value}")

        change_batch = {
          comment: 'ACME DNS-01 challenge - managed by CertManager',
          changes: [
            {
              action: 'UPSERT',
              resource_record_set: {
                name: fqdn,
                type: 'TXT',
                ttl: 60,
                resource_records: [
                  { value: quoted_value }
                ]
              }
            }
          ]
        }

        response = @client.change_resource_record_sets(
          hosted_zone_id: @hosted_zone_id,
          change_batch: change_batch
        )

        # Wait for the change to propagate within Route 53
        wait_for_change(response.change_info.id)

        # Return the record name as the identifier
        { record_name: fqdn, value: value }.to_json
      end

      # Remove a TXT record via Route 53
      #
      # @param domain [String] The domain that was validated
      # @param record_id [String] JSON string with record_name and value
      # @param value [String] The challenge value (used if record_id doesn't contain it)
      # @return [Boolean] True if successful
      def remove_txt_record(domain, record_id, value = nil)
        record_info = parse_record_id(record_id, value)
        fqdn = ensure_fqdn(record_info[:record_name])

        quoted_value = %("#{record_info[:value]}")

        change_batch = {
          comment: 'ACME DNS-01 challenge cleanup - managed by CertManager',
          changes: [
            {
              action: 'DELETE',
              resource_record_set: {
                name: fqdn,
                type: 'TXT',
                ttl: 60,
                resource_records: [
                  { value: quoted_value }
                ]
              }
            }
          ]
        }

        begin
          @client.change_resource_record_sets(
            hosted_zone_id: @hosted_zone_id,
            change_batch: change_batch
          )
        rescue Aws::Route53::Errors::InvalidChangeBatch => e
          # Ignore "record not found" errors during cleanup
          raise DNSProviderError, "Route 53 failed to remove TXT record: #{e.message}" unless e.message.include?('not found')
        end

        true
      end

      # Find existing TXT records matching criteria
      #
      # @param domain [String] The domain to search
      # @param record_name [String] The record name to find
      # @return [Array<Hash>] Matching records
      def find_txt_records(domain, record_name)
        fqdn = ensure_fqdn(record_name)

        response = @client.list_resource_record_sets(
          hosted_zone_id: @hosted_zone_id,
          start_record_name: fqdn,
          start_record_type: 'TXT',
          max_items: 100
        )

        records = []
        response.resource_record_sets.each do |rrs|
          next unless rrs.type == 'TXT' && rrs.name == fqdn

          rrs.resource_records.each do |rr|
            val = unquote_txt_value(rr.value)
            records << {
              id: { record_name: rrs.name, value: val }.to_json,
              record_name: rrs.name,
              value: val
            }
          end
        end

        records
      end

      # List all TXT records in the hosted zone
      #
      # @param domain [String] Optional domain filter
      # @return [Array<Hash>] All TXT records
      def list_records(domain = nil)
        records = []
        params = { hosted_zone_id: @hosted_zone_id }

        loop do
          response = @client.list_resource_record_sets(params)

          response.resource_record_sets.each do |rrs|
            next unless rrs.type == 'TXT'
            next if domain && !rrs.name.end_with?("#{domain}.")

            rrs.resource_records.each do |rr|
              records << {
                'record' => rrs.name,
                'type' => rrs.type,
                'value' => unquote_txt_value(rr.value),
                'ttl' => rrs.ttl
              }
            end
          end

          break unless response.is_truncated

          params[:start_record_name] = response.next_record_name
          params[:start_record_type] = response.next_record_type
        end

        records
      end

      private

      def create_client(credentials)
        require 'aws-sdk-route53'

        client_options = { region: @region }

        # Use explicit credentials if provided
        if credentials['access_key_id'] && credentials['secret_access_key']
          client_options[:access_key_id] = credentials['access_key_id']
          client_options[:secret_access_key] = credentials['secret_access_key']
          client_options[:session_token] = credentials['session_token'] if credentials['session_token']
        end

        Aws::Route53::Client.new(client_options)
      rescue LoadError
        raise DNSProviderError, "AWS SDK not found. Install with: gem install aws-sdk-route53"
      end

      def wait_for_change(change_id)
        # Wait up to 60 seconds for the change to complete
        max_attempts = 12
        attempts = 0

        loop do
          response = @client.get_change(id: change_id)
          status = response.change_info.status

          return true if status == 'INSYNC'

          attempts += 1
          break if attempts >= max_attempts

          sleep 5
        end

        true # Continue even if not fully synced
      end

    end
  end
end
