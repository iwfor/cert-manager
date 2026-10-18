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
    assert_equal ['config.v2.yml'], Dir.children(File.dirname(@path)) - ['config.v2.yml.lock']
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

  def save_with(marker)
    writer = CertManager::ConfigWriter.new(@path, create: true)
    writer.data['marker'] = marker
    writer.save
  end

  def test_saves_in_the_same_second_keep_separate_backups
    save_with(0)
    backups = (1..4).map { |i| save_with(i) }
    assert_equal 4, backups.uniq.size
    assert_equal [0, 1, 2, 3], backups.map { |b| YAML.load_file(b)['marker'] }
  end

  def test_old_backups_are_pruned
    save_with(0)
    (CertManager::ConfigWriter::BACKUPS_KEPT + 5).times { |i| save_with(i + 1) }
    assert_equal CertManager::ConfigWriter::BACKUPS_KEPT, Dir["#{@path}.*.bak"].size
  end

  def test_symlinked_config_is_written_through
    real = File.join(@dir, 'real.yml')
    File.write(real, YAML.dump('version' => 2))
    File.chmod(0o600, real)
    FileUtils.mkdir_p(File.dirname(@path))
    File.symlink(real, @path)
    writer = CertManager::ConfigWriter.new(@path)
    writer.data['marker'] = 'x'
    writer.save
    assert File.symlink?(@path)
    assert_equal 'x', YAML.load_file(real)['marker']
  end

  def test_concurrent_modification_is_detected
    save_with(0)
    first = CertManager::ConfigWriter.new(@path)
    second = CertManager::ConfigWriter.new(@path)
    first.data['a'] = 1
    first.save
    second.data['b'] = 2
    error = assert_raise(CertManager::ConfigError) { second.save }
    assert_match(/modified by another process/, error.message)
    assert_equal({ 'version' => 2, 'marker' => 0, 'a' => 1 }, YAML.load_file(@path))
  end

  def test_tolerates_malformed_provider_entries
    FileUtils.mkdir_p(File.dirname(@path))
    File.write(@path, YAML.dump('version' => 2, 'providers' => { 'broken' => nil }))
    writer = CertManager::ConfigWriter.new(@path)
    assert_equal false, writer.encrypted_values?
    assert_equal({}, writer.zones_by_provider)
  end
end
