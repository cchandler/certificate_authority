require 'rubygems'
require 'bundler'
require 'rspec'
require 'rspec/core/rake_task'

begin
  Bundler.setup(:default, :development)
rescue Bundler::BundlerError => e
  $stderr.puts e.message
  $stderr.puts "Run `bundle install` to install missing gems"
  exit e.status_code
end

require 'rake'

desc 'Default: run specs.'
task :default => :spec

require 'jeweler'
Jeweler::Tasks.new do |gem|
  # gem is a Gem::Specification... see http://docs.rubygems.org/read/chapter/20 for more options
  gem.name = "certificate_authority"
  gem.homepage = "https://github.com/cchandler/certificate_authority"
  gem.license = "MIT"
  gem.summary = 'Ruby gem for managing the core functions outlined in RFC-3280 for PKI'
  # gem.description = ''
  gem.email = "squanderingtime@gmail.com"
  gem.authors = ["Chris Chandler"]
end
Jeweler::RubygemsDotOrgTasks.new

task :spec do
  Rake::Task["spec:units"].invoke
end

namespace :spec do
  desc "Run unit specs."
  RSpec::Core::RakeTask.new(:units) do |t|
    t.rspec_opts = ['--colour --format progress --tag ~pkcs11']
  end

  desc "Run integration specs."
  RSpec::Core::RakeTask.new(:integrations) do |t|
    t.rspec_opts   = ['--colour --format progress']
  end
end

RSpec::Core::RakeTask.new(:doc) do |t|
  t.rspec_opts   = ['--format specdoc ']
end
