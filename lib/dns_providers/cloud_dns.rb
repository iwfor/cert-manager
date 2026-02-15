# frozen_string_literal: true

require_relative 'base'

module CertManager
  module DNSProviders
    # Google Cloud DNS provider implementation
    # Uses the Google Cloud DNS API to manage DNS TXT records
    #
    # Required credentials:
    #   - project_id: GCP project ID containing the managed zone
    #   - managed_zone: Name of the Cloud DNS managed zone
    #
    # Optional credentials:
    #   - credentials_file: Path to service account JSON key file
    #
    # If credentials_file is not provided, the provider uses Application Default
    # Credentials (ADC), which checks:
    #   1. GOOGLE_APPLICATION_CREDENTIALS environment variable
    #   2. Default service account (on GCE/GKE/Cloud Run)
    #   3. User credentials from `gcloud auth application-default login`
    #
    # @example Configuration with service account key
    #   dns_providers:
    #     gcp_dns:
    #       type: cloud_dns
    #       project_id: my-project-123
    #       managed_zone: my-zone
    #       credentials_file: /path/to/service-account.json
    #
    # @example Configuration using Application Default Credentials
    #   dns_providers:
    #     gcp_dns:
    #       type: cloud_dns
    #       project_id: my-project-123
    #       managed_zone: my-zone
    #
    class CloudDNS < Base
      def self.provider_type
        'cloud_dns'
      end

      def self.required_credentials
        %w[project_id managed_zone]
      end

      def initialize(name, credentials)
        super
        @project_id = credentials['project_id']
        @managed_zone = credentials['managed_zone']
        @credentials_file = credentials['credentials_file']

        @service = create_service
      end

      # Add a TXT record via Cloud DNS
      #
      # @param domain [String] The domain being validated
      # @param record_name [String] Full DNS record name
      # @param value [String] The challenge token value
      # @return [String] JSON identifier for removal
      def add_txt_record(domain, record_name, value)
        fqdn = ensure_fqdn(record_name)

        # Check if record already exists
        existing = get_existing_record(fqdn)

        change = Google::Apis::DnsV1::Change.new
        change.additions = []
        change.deletions = []

        # TXT records need to be quoted
        quoted_value = %("#{value}")

        if existing
          # Delete the old record and add new one with additional value
          change.deletions << existing

          new_record = Google::Apis::DnsV1::ResourceRecordSet.new(
            name: fqdn,
            type: 'TXT',
            ttl: 60,
            rrdatas: existing.rrdatas + [quoted_value]
          )
          change.additions << new_record
        else
          # Create new record
          new_record = Google::Apis::DnsV1::ResourceRecordSet.new(
            name: fqdn,
            type: 'TXT',
            ttl: 60,
            rrdatas: [quoted_value]
          )
          change.additions << new_record
        end

        response = @service.create_change(@project_id, @managed_zone, change)
        wait_for_change_completion(response.id)

        { record_name: fqdn, value: value }.to_json
      end

      # Remove a TXT record via Cloud DNS
      #
      # @param domain [String] The domain that was validated
      # @param record_id [String] JSON string with record_name and value
      # @param value [String] The challenge value (used if record_id doesn't contain it)
      # @return [Boolean] True if successful
      def remove_txt_record(domain, record_id, value = nil)
        record_info = parse_record_id(record_id, value)
        fqdn = ensure_fqdn(record_info[:record_name])

        existing = get_existing_record(fqdn)
        return true unless existing

        quoted_value = %("#{record_info[:value]}")
        remaining_values = existing.rrdatas.reject { |v| v == quoted_value }

        change = Google::Apis::DnsV1::Change.new
        change.deletions = [existing]
        change.additions = []

        if remaining_values.any?
          # Keep other values
          new_record = Google::Apis::DnsV1::ResourceRecordSet.new(
            name: fqdn,
            type: 'TXT',
            ttl: existing.ttl,
            rrdatas: remaining_values
          )
          change.additions << new_record
        end

        @service.create_change(@project_id, @managed_zone, change)
        true
      rescue Google::Apis::ClientError => e
        raise DNSProviderError, "Cloud DNS failed to remove TXT record: #{e.message}" unless e.message.include?('notFound')

        true
      end

      # Find existing TXT records matching criteria
      #
      # @param domain [String] The domain to search
      # @param record_name [String] The record name to find
      # @return [Array<Hash>] Matching records
      def find_txt_records(domain, record_name)
        fqdn = ensure_fqdn(record_name)

        existing = get_existing_record(fqdn)
        return [] unless existing

        existing.rrdatas.map do |val|
          { record_name: existing.name, value: unquote_txt_value(val) }
        end
      end

      # Remove all ACME challenge records for a domain
      #
      # @param domain [String] The domain to clean up
      # @return [Integer] Number of records removed
      def cleanup_challenge_records(domain)
        record_name = "_acme-challenge.#{domain}"
        records = find_txt_records(domain, record_name)

        return 0 if records.empty?

        fqdn = ensure_fqdn(record_name)
        existing = get_existing_record(fqdn)

        return 0 unless existing

        change = Google::Apis::DnsV1::Change.new
        change.deletions = [existing]
        change.additions = []

        @service.create_change(@project_id, @managed_zone, change)
        records.length
      end

      # List all TXT records in the managed zone
      #
      # @param domain [String] Optional domain filter
      # @return [Array<Hash>] All TXT records
      def list_records(domain = nil)
        records = []
        page_token = nil

        loop do
          response = @service.list_resource_record_sets(
            @project_id,
            @managed_zone,
            page_token: page_token
          )

          response.rrsets&.each do |rrs|
            next unless rrs.type == 'TXT'
            next if domain && !rrs.name.end_with?("#{domain}.")

            rrs.rrdatas.each do |val|
              records << {
                'record' => rrs.name,
                'type' => rrs.type,
                'value' => unquote_txt_value(val),
                'ttl' => rrs.ttl
              }
            end
          end

          page_token = response.next_page_token
          break unless page_token
        end

        records
      end

      private

      def create_service
        require 'google/apis/dns_v1'

        service = Google::Apis::DnsV1::DnsService.new
        service.client_options.application_name = 'CertManager'
        service.client_options.application_version = CertManager::VERSION

        # Set up authorization
        if @credentials_file
          service.authorization = Google::Auth::ServiceAccountCredentials.make_creds(
            json_key_io: File.open(@credentials_file),
            scope: 'https://www.googleapis.com/auth/ndev.clouddns.readwrite'
          )
        else
          require 'googleauth'
          service.authorization = Google::Auth.get_application_default(
            'https://www.googleapis.com/auth/ndev.clouddns.readwrite'
          )
        end

        service
      rescue LoadError
        raise DNSProviderError, "Google Cloud DNS SDK not found. Install with: gem install google-apis-dns_v1 googleauth"
      end

      def get_existing_record(fqdn)
        response = @service.list_resource_record_sets(
          @project_id,
          @managed_zone,
          name: fqdn,
          type: 'TXT'
        )

        response.rrsets&.find { |r| r.name == fqdn && r.type == 'TXT' }
      end

      def wait_for_change_completion(change_id)
        max_attempts = 24  # 2 minutes max
        attempts = 0

        loop do
          change = @service.get_change(@project_id, @managed_zone, change_id)
          return true if change.status == 'done'

          attempts += 1
          break if attempts >= max_attempts

          sleep 5
        end

        true # Continue even if not fully complete
      end

    end
  end
end
