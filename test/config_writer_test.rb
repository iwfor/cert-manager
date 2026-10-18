# frozen_string_literal: true

require_relative 'test_helper'
require_relative '../lib/config_writer'

class ConfigWriterTest < Test::Unit::TestCase
  def setup
    @dir = Dir.mktmpdir('cert_manager_writer')
    @path = File.join(@dir, 'sub', 'config.v2.yml')
  end

  def teardown
    FileUtils.rm_rf(@dir)
  end

  def test_create_writes_owner_only_file
    writer = CertManager::ConfigWriter.new(@path, create: true)
    writer.providers['cf'] = { 'type' => 'cloudflare' }
    assert_nil writer.save
    assert_equal 0o600, File.stat(@path).mode & 0o777
    assert_equal 0o700, File.stat(File.dirname(@path)).mode & 0o777
    assert_equal 2, YAML.load_file(@path)['version']
  end

  def test_save_keeps_backup_of_previous_version
    writer = CertManager::ConfigWriter.new(@path, create: true)
    writer.save
    writer = CertManager::ConfigWriter.new(@path)
    writer.providers['cf'] = { 'type' => 'cloudflare' }
    backup = writer.save
    assert File.exist?(backup)
    assert_equal 0o600, File.stat(backup).mode & 0o777
    assert_nil YAML.load_file(backup)['providers']
    assert_equal 'cloudflare', YAML.load_file(@path)['providers']['cf']['type']
  end

  def test_leaves_no_temp_files
    CertManager::ConfigWriter.new(@path, create: true).save
    assert_equal ['config.v2.yml'], Dir.children(File.dirname(@path))
  end

  def test_missing_file_without_create
    assert_raise(CertManager::ConfigError) { CertManager::ConfigWriter.new(@path) }
  end

  def test_rejects_v1_file
    FileUtils.mkdir_p(File.dirname(@path))
    File.write(@path, YAML.dump('dns_providers' => {}))
    error = assert_raise(CertManager::ConfigError) { CertManager::ConfigWriter.new(@path) }
    assert_match(/convert-config/, error.message)
  end
end
