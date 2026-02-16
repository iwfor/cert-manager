# frozen_string_literal: true

require 'rake/testtask'

Rake::TestTask.new(:test) do |t|
  t.libs << 'test'
  t.libs << 'lib'
  t.test_files = FileList['test/**/*_test.rb']
end

file 'logo.png' => 'logo.svg' do
  sh 'rsvg-convert logo.svg -w 256 -h 256 -o logo.png'
end

task default: :test
