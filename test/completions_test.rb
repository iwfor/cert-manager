# frozen_string_literal: true

require 'open3'
require_relative 'test_helper'

class CompletionsTest < Test::Unit::TestCase
  include TestFixtures

  def setup
    @dir = Dir.mktmpdir('cert_manager_completions')
    @config = File.join(@dir, 'config.v2.yml')
    run_cli('-c', @config, 'init', '--email', 'a@example.org')
    run_cli('-c', @config, 'add-provider', 'cf', '--type', 'cloudflare', '--key-stdin', '--no-verify', '--zone', 'example.com', stdin: "t\n")
    doc = YAML.load_file(@config)
    doc['certificates'] = [{ 'name' => 'web', 'domains' => ['www.example.com'] }, { 'domains' => ['bare.example.com'] }]
    File.write(@config, YAML.dump(doc))
  end

  def teardown
    FileUtils.rm_rf(@dir)
  end

  def script(shell, program: 'cert_manager.rb')
    CertManager::Completions.generate(shell, program: program, executable: '/opt/cm/cert_manager.rb')
  end

  def test_detect_shell_from_env
    assert_equal 'bash', CertManager::Completions.detect_shell(nil, '/bin/bash')
    assert_equal 'zsh', CertManager::Completions.detect_shell(nil, '/usr/local/bin/zsh')
  end

  def test_explicit_shell_overrides_env
    assert_equal 'bash', CertManager::Completions.detect_shell('bash', '/bin/zsh')
  end

  def test_unsupported_or_unset_shell
    assert_raise(CertManager::CLI::UsageError) { CertManager::Completions.detect_shell(nil, '/usr/bin/fish') }
    assert_raise(CertManager::CLI::UsageError) { CertManager::Completions.detect_shell(nil, nil) }
    assert_raise(CertManager::CLI::UsageError) { CertManager::Completions.detect_shell('fish', '/bin/bash') }
  end

  # Maintenance guard: every visible command and flag must show up in both scripts,
  # so adding a command or option through the registry keeps completions current.
  def test_every_command_and_flag_is_completed
    %w[bash zsh].each do |shell|
      text = script(shell)
      CertManager::Completions.commands.each do |cmd|
        assert_include text, cmd.name, "#{shell} completion is missing command #{cmd.name}"
        CertManager::Completions.flags_for(cmd).each do |flag|
          assert_include text, flag, "#{shell} completion is missing #{flag} for #{cmd.name}"
        end
      end
    end
  end

  def test_hidden_commands_are_not_advertised
    assert_not_include CertManager::Completions.commands.map(&:name), '__complete'
    assert_no_match(/'__complete:/, script('zsh'))
    assert_no_match(/compgen -W "[^"]*__complete/, script('bash'))
  end

  def test_scripts_are_valid_syntax
    { 'bash' => 'bash', 'zsh' => 'zsh' }.each do |shell, bin|
      next unless system("command -v #{bin} >/dev/null 2>&1")

      _, err, status = Open3.capture3(bin, '-n', stdin_data: script(shell))
      assert status.success?, "#{shell} syntax error: #{err}"
    end
  end

  def test_program_name_is_configurable
    assert_match(/complete -F _my_cm my-cm/, script('bash', program: 'my-cm'))
    assert_match(/compdef _my_cm my-cm/, script('zsh', program: 'my-cm'))
  end

  def test_executable_path_is_used_for_callbacks
    assert_include script('bash'), '/opt/cm/cert_manager.rb'
  end

  def test_candidates_from_v2_config
    c = CertManager::Completions
    assert_equal %w[web bare.example.com], c.candidates('certificate', @config)
    assert_equal ['cf'], c.candidates('provider', @config)
    assert_equal ['example.com'], c.candidates('zone', @config)
    assert_equal [], c.candidates('zone', @config, 'nonexistent')
    assert_equal CertManager::DNSProviders.available_types, c.candidates('type')
    assert_equal %w[bash zsh], c.candidates('shell')
    assert_include c.candidates('command'), 'add-zone'
  end

  def test_candidates_from_v1_config
    v1 = write_config(@dir)
    assert_equal ['test_cf'], CertManager::Completions.candidates('provider', v1)
    assert_equal ['webserver'], CertManager::Completions.candidates('certificate', v1)
  end

  def test_candidates_never_raise
    assert_equal [], CertManager::Completions.candidates('certificate', File.join(@dir, 'missing.yml'))
    assert_equal [], CertManager::Completions.candidates('bogus')
    File.write(File.join(@dir, 'bad.yml'), ": : not yaml [")
    assert_equal [], CertManager::Completions.candidates('provider', File.join(@dir, 'bad.yml'))
  end

  def test_cli_completions_command_uses_shell_env
    old = ENV['SHELL']
    ENV['SHELL'] = '/bin/zsh'
    status, out, = run_cli('completions')
    assert_equal 0, status
    assert_match(/\A#compdef/, out)
    status, out, = run_cli('completions', 'bash')
    assert_equal 0, status
    assert_match(/^complete -F/, out)
    status, out, = run_cli('completions', '--shell', 'bash')
    assert_match(/^complete -F/, out)
    ENV['SHELL'] = '/usr/bin/fish'
    status, _, err = run_cli('completions')
    assert_equal 2, status
    assert_match(/bash, zsh/, err)
  ensure
    ENV['SHELL'] = old
  end

  def test_cli_complete_callback_prints_candidates
    status, out, = run_cli('-c', @config, '__complete', 'provider')
    assert_equal 0, status
    assert_equal "cf\n", out
  end

  def test_bash_script_completes_dynamic_values
    skip 'bash not available' unless system('command -v bash >/dev/null 2>&1')
    exe = File.expand_path('../cert_manager.rb', __dir__)
    script = CertManager::Completions.generate('bash', program: 'cert_manager.rb', executable: exe)
    driver = <<~SH
      #{script}
      COMP_WORDS=(cert_manager.rb -c #{@config} request "")
      COMP_CWORD=4
      _cert_manager_rb
      echo "${COMPREPLY[*]}"
    SH
    out, err, status = Open3.capture3('bash', stdin_data: driver)
    assert status.success?, err
    assert_equal 'web bare.example.com', out.strip
  end
end
