module CertificateAuthority
  class OCSPHandler
    include ActiveModel::Validations
    
    attr_accessor :ocsp_request
    attr_accessor :certificate_ids
    
    attr_accessor :certificates
    attr_accessor :parent
    
    attr_accessor :ocsp_response_body
    
    validate do |crl|
      errors.add :parent, "A parent entity must be set" if parent.nil?
    end
    validate :all_certificates_available
    
    def initialize
      self.certificates = {}
    end
    
    def <<(cert)
      self.certificates[cert.serial_number.number.to_s] = cert
    end
    
    def extract_certificate_serials
      raise "No valid OCSP request was supplied" if self.ocsp_request.nil?
      openssl_request = OpenSSL::OCSP::Request.new(self.ocsp_request)
      
      self.certificate_ids = openssl_request.certid.collect do |cert_id|
        cert_id.serial
      end
      
      self.certificate_ids
    end
    
    
    def response
      raise "Invalid response" unless valid?
      
      openssl_ocsp_response = OpenSSL::OCSP::BasicResponse.new
      openssl_ocsp_request = OpenSSL::OCSP::Request.new(self.ocsp_request)
      openssl_ocsp_response.copy_nonce(openssl_ocsp_request)
      
      openssl_ocsp_request.certid.each do |cert_id|
        certificate = self.certificates[cert_id.serial.to_s]
        
        openssl_ocsp_response.add_status(cert_id, 
        OpenSSL::OCSP::V_CERTSTATUS_GOOD, 0, 
          0, 0, 30, nil)
      end
      
      
      openssl_ocsp_response.sign(OpenSSL::X509::Certificate.new(self.parent.to_pem), self.parent.key_material.private_key, nil, nil)
      final_response = OpenSSL::OCSP::Response.create(OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL, openssl_ocsp_response)
      self.ocsp_response_body = final_response
      self.ocsp_response_body
    end
    
    def to_der
      raise "No signed OCSP response body available" if self.ocsp_response_body.nil?
      self.ocsp_response_body.to_der
    end
    
    private
    
    def all_certificates_available
      openssl_ocsp_request = OpenSSL::OCSP::Request.new(self.ocsp_request)
      
      openssl_ocsp_request.certid.each do |cert_id|
        certificate = self.certificates[cert_id.serial.to_s]
        errors.add(:base, "Certificate #{cert_id.serial} has not been added yet") if certificate.nil?
      end
    end
    
  end
end