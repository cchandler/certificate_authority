module CertificateAuthority
  class OCSPResponseBuilder
    attr_accessor :ocsp_response
    attr_accessor :verification_mechanism
    attr_accessor :ocsp_request_reader
    attr_accessor :parent
    attr_accessor :next_update

    GOOD = OpenSSL::OCSP::V_CERTSTATUS_GOOD
    REVOKED = OpenSSL::OCSP::V_CERTSTATUS_REVOKED

    NO_REASON=0
    KEY_COMPROMISED=OpenSSL::OCSP::REVOKED_STATUS_KEYCOMPROMISE
    UNSPECIFIED=OpenSSL::OCSP::REVOKED_STATUS_UNSPECIFIED

    def build_response()
      raise "Requires a parent for signing" if @parent.nil?
      if @verification_mechanism.nil?
        ## If no verification callback is provided we're marking it GOOD
        @verification_mechanism = lambda {|cert_id| [GOOD,NO_REASON] }
      end

      @ocsp_request_reader.ocsp_request.certid.each do |cert_id|
        result,reason = verification_mechanism.call(cert_id.serial)

        ## cert_id, status, reason, rev_time, this update, next update, ext
        ## - unit of time is seconds
        ## - rev_time is currently set to "now"
        @ocsp_response.add_status(cert_id,
        result, reason,
          0, 0, @next_update, nil)
      end

      @ocsp_response.sign(OpenSSL::X509::Certificate.new(@parent.to_pem), @parent.key_material.private_key, nil, nil)
      OpenSSL::OCSP::Response.create(OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL, @ocsp_response)
    end

    def self.from_request_reader(request_reader,verification_mechanism=nil)
      response_builder = OCSPResponseBuilder.new
      response_builder.ocsp_request_reader = request_reader

      ocsp_response = OpenSSL::OCSP::BasicResponse.new
      ocsp_response.copy_nonce(request_reader.ocsp_request)
      response_builder.ocsp_response = ocsp_response
      response_builder.next_update = 60*15 #Default of 15 minutes
      response_builder
    end
  end

  class OCSPRequestReader
    attr_accessor :raw_ocsp_request
    attr_accessor :ocsp_request

    def serial_numbers
      @ocsp_request.certid.collect do |cert_id|
        cert_id.serial
      end
    end

    def self.from_der(request_body)
      reader = OCSPRequestReader.new
      reader.raw_ocsp_request = request_body
      reader.ocsp_request = OpenSSL::OCSP::Request.new(request_body)

      reader
    end
  end

  ## DEPRECATED
  class OCSPHandler
    include Validations

    attr_accessor :ocsp_request
    attr_accessor :certificate_ids

    attr_accessor :certificates
    attr_accessor :parent

    attr_accessor :ocsp_response_body

    def validate
      errors.add :parent, "A parent entity must be set" if parent.nil?
      all_certificates_available
    end

    def initialize
      self.certificates = {}
    end

    def <<(cert)
      self.certificates[cert.serial_number.number.to_s] = cert
    end

    def extract_certificate_serials
      openssl_request = OpenSSL::OCSP::Request.new(@ocsp_request)

      if openssl_request.certid.nil?
        raise "Invalid openssl request"
      end
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
