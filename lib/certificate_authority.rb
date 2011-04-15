$:.unshift(File.dirname(__FILE__)) unless $:.include?(File.dirname(__FILE__)) || $:.include?(File.expand_path(File.dirname(__FILE__)))

#Exterior requirements
require 'openssl'
require 'active_model'

#Internal modules
require 'certificate_authority/signing_entity'
require 'certificate_authority/distinguished_name'
require 'certificate_authority/serial_number'
require 'certificate_authority/key_material'
require 'certificate_authority/extensions'
require 'certificate_authority/certificate'

module CertificateAuthority
end