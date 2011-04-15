require 'rubygems'
require 'rake/clean'
require 'rspec'
require 'rspec/core/rake_task'

desc 'Default: run specs.'
task :default => :spec

begin
  require 'jeweler'

  Jeweler::Tasks.new do |gem|
    gem.name = 'certificate_authority'
    gem.summary = 'A library for most CA related functionality'
    gem.email = 'chris@flatterline.com'
    gem.homepage = 'http://github.com/cchandler/certificate_authority'
    gem.authors = ['Chris Chandler']
    gem.rubyforge_project = 'certificate_authority'
    gem.platform           = Gem::Platform::RUBY
    gem.files              = FileList['{bin,lib}/**/*'].to_a
    gem.require_path       = 'lib'
    gem.test_files         = FileList['{spec}/**/{*spec.rb,*helper.rb}'].to_a
    #gem.has_rdoc           = true
    gem.extra_rdoc_files   = ['README.markdown', 'LICENSE']

    gem.add_dependency('activemodel', '3.0.6')
  end
rescue LoadError
  puts 'Jeweler not available. Install it with: sudo gem install technicalpickles-jeweler -s http://gems.github.com'
end

task :spec do
  Rake::Task["spec:units"].invoke
end

namespace :spec do
  desc "Run unit specs."
  RSpec::Core::RakeTask.new(:units) do |t|
    t.rspec_opts = ['--colour --format progress']
  end

  desc "Run integration specs. Requires AWS_ACCESS_KEY and AWS_SECRET_KEY."
  RSpec::Core::RakeTask.new(:integrations) do |t|
    t.rspec_opts   = ['--colour --format progress']
  end
end

RSpec::Core::RakeTask.new(:doc) do |t|
  t.rspec_opts   = ['--format specdoc --dry-run --colour']
end
