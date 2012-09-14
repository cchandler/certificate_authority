require 'rubygems'
require 'rspec'
require 'pathname'

SPECDIR = Pathname(__FILE__).dirname
require SPECDIR.join('..', 'lib', 'certificate_authority').to_s

def sample_file(name)
  SPECDIR.join("samples", name)
end

