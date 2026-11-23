# frozen_string_literal: true

source 'https://rubygems.org'

ruby file: '.ruby-version'

# Bundled (not default) gems since Ruby 3.x; must be declared to load under Bundler
gem 'base64'  # secret_store
gem 'logger'  # default gem, becomes bundled in Ruby 3.5
gem 'rexml'   # namecheap provider

# Optional DNS provider SDKs (loaded lazily only when the provider is used).
# Enable with: bundle config set --local with route53 cloud_dns
group :route53, optional: true do
  gem 'aws-sdk-route53'
end

group :cloud_dns, optional: true do
  gem 'google-apis-dns_v1'
  gem 'googleauth'
end

group :development, :test do
  gem 'rake'
  gem 'test-unit'
end
