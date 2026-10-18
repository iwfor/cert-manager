# frozen_string_literal: true

require_relative '../completions'

module CertManager
  module CLI
    command 'completions', group: :tools, summary: 'Print a shell completion script (bash or zsh)',
            args: [arg('shell', :shell, required: false, desc: 'bash or zsh (default: from $SHELL)')],
            options: [
              option(:shell, long: '--shell', arg: 'SHELL', values: Completions::SHELLS, desc: 'Shell to generate for (same as the argument)'),
              option(:program, long: '--program', arg: 'NAME', desc: 'Command name to register completion for (default: this script\'s name)')
            ],
            description: "Install for bash (add to ~/.bashrc):  eval \"$(#{program} completions)\"\n" \
                         "Install for zsh (add to ~/.zshrc, after compinit):  eval \"$(#{program} completions)\"\n" \
                         "or save it as a file named _#{program} in a directory on your $fpath.\n" \
                         "Candidates for certificates, providers and zones are read from your config as you type.",
            examples: ['completions', 'completions zsh > ~/.zsh/completions/_cert_manager.rb'] do |ctx|
      shell = Completions.detect_shell(ctx.args.first || ctx.options[:shell])
      puts Completions.generate(shell, program: ctx.options[:program] || program, executable: File.expand_path($PROGRAM_NAME))
    end

    # Called by the generated scripts; must never fail or print anything but candidates
    command '__complete', group: :hidden, summary: 'Internal: list completion candidates',
            args: [arg('kind', nil), arg('context', nil, required: false)],
            globals: %i[config] do |ctx|
      puts Completions.candidates(ctx.args[0], ctx.options[:config], ctx.args[1])
    end
  end
end
