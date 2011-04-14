$:.unshift(File.dirname(__FILE__)) unless $:.include?(File.dirname(__FILE__)) || $:.include?(File.expand_path(File.dirname(__FILE__)))

#Exterior requirements
require 'openssl'
require 'active_model'

#Internal modules
require 'certificate-authority/signing_entity'
require 'certificate-authority/distinguished_name'
require 'certificate-authority/serial_number'
require 'certificate-authority/key_material'
require 'certificate-authority/extensions'
require 'certificate-authority/certificate'

module CertificateAuthority
end