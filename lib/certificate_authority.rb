$:.unshift(File.dirname(__FILE__)) unless $:.include?(File.dirname(__FILE__)) || $:.include?(File.expand_path(File.dirname(__FILE__)))

#Exterior requirements
require 'openssl'

#Internal modules
require 'certificate_authority/core_extensions'
require 'certificate_authority/signing_entity'
require 'certificate_authority/revocable'
require 'certificate_authority/validations'
require 'certificate_authority/distinguished_name'
require 'certificate_authority/serial_number'
require 'certificate_authority/key_material'
require 'certificate_authority/pkcs11_key_material'
require 'certificate_authority/extensions'
require 'certificate_authority/certificate'
require 'certificate_authority/certificate_revocation_list'
require 'certificate_authority/ocsp_handler'
require 'certificate_authority/signing_request'

module CertificateAuthority
end
