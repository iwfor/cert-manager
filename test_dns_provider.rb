#!/usr/bin/env ruby
# frozen_string_literal: true

# Test script for DNS providers
# Tests adding and removing TXT records without involving certbot

require 'yaml'
require 'optparse'
require_relative 'lib/dns_providers'
require_relative 'lib/file_permissions'

options = {
  config: File.expand_path('~/.config/cert_manager/config.yml'),
  provider: nil,
  domain: nil,
  keep: false,
  verbose: false,
  list_only: false,
  wait: 10
}

parser = OptionParser.new do |opts|
  opts.banner = "Usage: #{$PROGRAM_NAME} [options]"
  opts.separator ""
  opts.separator "Tests DNS provider by creating and removing a test TXT record."
  opts.separator ""
  opts.separator "Options:"

  opts.on('-c', '--config PATH', 'Path to configuration file') do |path|
    options[:config] = path
  end

  opts.on('-p', '--provider NAME', 'DNS provider name from config (required)') do |name|
    options[:provider] = name
  end

  opts.on('-d', '--domain DOMAIN', 'Domain to test with (required for add/remove tests)') do |domain|
    options[:domain] = domain
  end

  opts.on('-k', '--keep', 'Keep the test record (do not delete)') do
    options[:keep] = true
  end

  opts.on('-v', '--verbose', 'Show verbose output') do
    options[:verbose] = true
  end

  opts.on('-l', '--list', 'List existing DNS records only (requires -d)') do
    options[:list_only] = true
  end

  opts.on('-w', '--waiti SECONDS') do |sec|
    sec = sec.to_i
    options[:wait] = sec <= 0 ? 1 : sec
  end

  opts.on('-h', '--help', 'Show this help') do
    puts opts
    exit
  end
end

parser.parse!

unless options[:provider]
  puts "Error: --provider is required"
  puts parser
  exit 1
end

unless options[:domain] || options[:list_only] == false
  puts "Error: --domain is required"
  puts parser
  exit 1
end

# Load configuration
unless File.exist?(options[:config])
  puts "Error: Configuration file not found: #{options[:config]}"
  exit 1
end

CertManager::FilePermissions.check(options[:config])
config = YAML.safe_load(File.read(options[:config]))

unless config['dns_providers']&.key?(options[:provider])
  puts "Error: Provider '#{options[:provider]}' not found in configuration"
  puts "Available providers: #{config['dns_providers']&.keys&.join(', ') || 'none'}"
  exit 1
end

# Create provider instance
provider_config = config['dns_providers'][options[:provider]]
puts "Provider: #{options[:provider]} (#{provider_config['type']})"
puts "Domain: #{options[:domain]}" if options[:domain]
if options[:verbose]
  puts "Config: #{provider_config.reject { |k, _| k == 'api_key' && k == 'api_token' }.inspect}"
end
puts ""

begin
  provider = CertManager::DNSProviders.create(
    provider_config['type'],
    options[:provider],
    provider_config.reject { |k, _| k == 'type' }
  )
rescue => e
  puts "ERROR: Failed to create provider: #{e.message}"
  puts e.backtrace.first(10).join("\n") if options[:verbose]
  exit 1
end

# List-only mode
if options[:list_only]
  puts "=" * 60
  puts "Listing DNS records"
  puts "=" * 60

  if provider.respond_to?(:list_records)
    begin
      records = provider.list_records(options[:domain])
      puts "Found #{records.length} record(s):"
      records.each do |r|
        if r.is_a?(Hash)
          puts "  #{r['type']&.ljust(6) || '?'} #{r['record'] || r[:record_name]} = #{r['value'] || r[:value]}"
        else
          puts "  #{r.inspect}"
        end
      end
    rescue => e
      puts "ERROR: #{e.message}"
      puts e.backtrace.first(5).join("\n") if options[:verbose]
    end
  else
    puts "Provider does not support listing records"
  end
  exit 0
end

unless options[:domain]
  puts "Error: --domain is required for add/remove tests"
  exit 1
end

# Test values
record_name = "_acme-challenge-test.#{options[:domain]}"
test_value = "test-#{Time.now.to_i}-#{rand(10000)}"
record_id = nil

puts "=" * 60
puts "TEST 1: Add TXT record"
puts "=" * 60
puts "Record: #{record_name}"
puts "Value: #{test_value}"
puts ""

begin
  print "Adding record... "
  record_id = provider.add_txt_record(options[:domain], record_name, test_value)
  puts "OK"
  puts "Record ID: #{record_id}"
rescue => e
  puts "FAILED"
  puts "Error: #{e.message}"
  puts e.backtrace.first(10).join("\n") if options[:verbose]
  exit 1
end

puts ""
puts "=" * 60
puts "TEST 2: Verify record exists (DNS lookup)"
puts "=" * 60

# Wait a moment for DNS
print "Waiting #{options[:wait]} seconds for DNS... "
sleep options[:wait]
puts "done"

begin
  print "Checking DNS... "
  if provider.record_exists?(record_name, test_value)
    puts "OK (record found)"
  else
    puts "WARNING: Record not found in DNS (may need more propagation time)"
  end
rescue => e
  puts "SKIPPED: #{e.message}"
end

# Test finding records (if supported)
if provider.respond_to?(:find_txt_records)
  puts ""
  puts "=" * 60
  puts "TEST 3: Find TXT records via API"
  puts "=" * 60

  begin
    print "Querying API... "
    records = provider.find_txt_records(options[:domain], record_name)
    puts "OK"
    puts "Found #{records.length} record(s):"
    records.each do |r|
      puts "  - #{r.inspect}"
    end
  rescue => e
    puts "FAILED"
    puts "Error: #{e.message}"
  end
end

unless options[:keep]
  puts ""
  puts "=" * 60
  puts "TEST 4: Remove TXT record"
  puts "=" * 60

  begin
    print "Removing record (ID: #{record_id})... "
    provider.remove_txt_record(options[:domain], record_id, test_value)
    puts "OK"
  rescue => e
    puts "FAILED"
    puts "Error: #{e.message}"
    puts e.backtrace.first(5).join("\n")
    exit 1
  end

  # Verify removal
  if provider.respond_to?(:find_txt_records)
    puts ""
    print "Verifying removal... "
    sleep 2
    begin
      records = provider.find_txt_records(options[:domain], record_name)
      if records.empty?
        puts "OK (record removed)"
      else
        puts "WARNING: Record still exists"
      end
    rescue => e
      puts "SKIPPED: #{e.message}"
    end
  end
else
  puts ""
  puts "Skipping removal (--keep specified)"
  puts "Record ID: #{record_id}"
  puts "To manually remove: use the 'cleanup' command or provider's web interface"
end

puts ""
puts "=" * 60
puts "TEST COMPLETE"
puts "=" * 60
