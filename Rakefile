require "bundler/gem_tasks"
require "rspec/core/rake_task"
require "rubocop/rake_task"

desc "Default: run specs."
task default: %i[spec]

task :spec do
  Rake::Task["spec:units"].invoke
end

namespace :spec do
  desc "Run unit specs."
  RSpec::Core::RakeTask.new(:units) do |t|
    t.rspec_opts = ["--colour --format progress --tag ~pkcs11"]
  end
end
