require 'rubygems'
require 'bundler/setup'
require 'certificate_authority'
require 'pathname'
require 'pry'

require 'coveralls'
Coveralls.wear!

SAMPLES_DIR = Pathname.new(__dir__).join('samples').freeze

def sample_file(name)
  SAMPLES_DIR.join(name)
end

