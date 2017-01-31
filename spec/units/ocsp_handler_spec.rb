require File.dirname(__FILE__) + '/units_helper'

describe CertificateAuthority::OCSPRequestReader do
  before(:each) do
    @root_certificate = CertificateAuthority::Certificate.new
    @root_certificate.signing_entity = true
    @root_certificate.subject.common_name = "OCSP Root"
    @root_certificate.key_material.generate_key(768)
    @root_certificate.serial_number.number = 1
    @root_certificate.sign!

    @certificate = CertificateAuthority::Certificate.new
    @certificate.key_material.generate_key(768)
    @certificate.subject.common_name = "http://questionablesite.com"
    @certificate.parent = @root_certificate
    @certificate.serial_number.number = 2
    @certificate.sign!

    @ocsp_request = OpenSSL::OCSP::Request.new
    openssl_cert_issuer = OpenSSL::X509::Certificate.new(@root_certificate.to_pem)
    openssl_cert_subject = OpenSSL::X509::Certificate.new(@certificate.to_pem)

    cert_id = OpenSSL::OCSP::CertificateId.new(openssl_cert_subject, openssl_cert_issuer)
    @ocsp_request.add_certid(cert_id)
    @ocsp_request_reader = CertificateAuthority::OCSPRequestReader.from_der(@ocsp_request.to_der)
  end

  it "should read in the DER encoded body" do
    expect(@ocsp_request_reader).not_to be_nil
  end

  it "should read out certificate serial numbers" do
    expect(@ocsp_request_reader.serial_numbers).to eq([2])
  end
end

describe CertificateAuthority::OCSPResponseBuilder do
  before(:each) do
    @root_certificate = CertificateAuthority::Certificate.new
    @root_certificate.signing_entity = true
    @root_certificate.subject.common_name = "OCSP Root"
    @root_certificate.key_material.generate_key(768)
    @root_certificate.serial_number.number = 1
    @root_certificate.sign!({"extensions" => {"keyUsage" => {"usage" => ["critical", "keyCertSign"] }} })

    @certificate = CertificateAuthority::Certificate.new
    @certificate.key_material.generate_key(768)
    @certificate.subject.common_name = "http://questionablesite.com"
    @certificate.parent = @root_certificate
    @certificate.serial_number.number = 2
    @certificate.sign!

    @ocsp_request = OpenSSL::OCSP::Request.new
    @ocsp_request.add_nonce
    openssl_cert_issuer = OpenSSL::X509::Certificate.new(@root_certificate.to_pem)
    openssl_cert_subject = OpenSSL::X509::Certificate.new(@certificate.to_pem)

    cert_id = OpenSSL::OCSP::CertificateId.new(openssl_cert_subject, openssl_cert_issuer)
    @ocsp_request.add_certid(cert_id)
    @ocsp_request_reader = CertificateAuthority::OCSPRequestReader.from_der(@ocsp_request.to_der)

    @response_builder = CertificateAuthority::OCSPResponseBuilder.from_request_reader(@ocsp_request_reader)
    @response_builder.parent = @root_certificate
  end

  it "should build from a OCSPRequestReader" do
    expect(@response_builder).not_to be_nil
    expect(@response_builder).to be_a(CertificateAuthority::OCSPResponseBuilder)
  end

  it "should build a response" do
    response = @response_builder.build_response
    expect(response).to be_a(OpenSSL::OCSP::Response)
  end

  it "should verify against the root" do
    response = @response_builder.build_response
    root_cert = OpenSSL::X509::Certificate.new(@root_certificate.to_pem)
    store = OpenSSL::X509::Store.new
    store.add_cert(root_cert)
    expect(response.basic.verify([root_cert],store)).to be_truthy
  end

  it "should have a configurable nextUpdate" do
    time = 30 * 60 # 30 minutes
    @response_builder.next_update=time
    response = @response_builder.build_response
    response.basic.status.each do |status|
      ## 3 seconds of wabble is OK
      expect(status[5]).to be_within(3).of(status[4] + time)
    end
  end

  describe "verification mechanisms" do
    it "should support an everything's OK default (though somewhat useless)" do
      response = @response_builder.build_response
      response.basic.status.each do |status|
        expect(status[1]).to eq(OpenSSL::OCSP::V_CERTSTATUS_GOOD)
      end
    end

    it "should support an overridable verification mechanism callback" do
      verification = lambda {|serial_number|
        [CertificateAuthority::OCSPResponseBuilder::REVOKED,CertificateAuthority::OCSPResponseBuilder::UNSPECIFIED]
      }
      @response_builder.verification_mechanism = verification
      response = @response_builder.build_response

      response.basic.status.each do |status|
        expect(status[1]).to eq(OpenSSL::OCSP::V_CERTSTATUS_REVOKED)
      end
    end
  end
end


## DEPRECATED
describe CertificateAuthority::OCSPHandler do
  before(:each) do
    @ocsp_handler = CertificateAuthority::OCSPHandler.new
    @root_certificate = CertificateAuthority::Certificate.new
    @root_certificate.signing_entity = true
    @root_certificate.subject.common_name = "OCSP Root"
    @root_certificate.key_material.generate_key(768)
    @root_certificate.serial_number.number = 1
    @root_certificate.sign!

    @certificate = CertificateAuthority::Certificate.new
    @certificate.key_material.generate_key(768)
    @certificate.subject.common_name = "http://questionablesite.com"
    @certificate.parent = @root_certificate
    @certificate.serial_number.number = 2
    @certificate.sign!

    @ocsp_request = OpenSSL::OCSP::Request.new
    openssl_cert_issuer = OpenSSL::X509::Certificate.new(@root_certificate.to_pem)
    openssl_cert_subject = OpenSSL::X509::Certificate.new(@certificate.to_pem)

    cert_id = OpenSSL::OCSP::CertificateId.new(openssl_cert_subject, openssl_cert_issuer)
    @ocsp_request.add_certid(cert_id)

    @ocsp_handler.ocsp_request = @ocsp_request.to_der
  end

  it "should be able to accept an OCSP Request" do
    @ocsp_handler.ocsp_request = @ocsp_request
    expect(@ocsp_handler.ocsp_request).not_to be_nil
  end

  it "should raise an error if you try and extract certificates without a raw request" do
    @ocsp_handler.extract_certificate_serials
    @ocsp_handler.ocsp_request = nil
    expect {@ocsp_handler.extract_certificate_serials}.to raise_error(RuntimeError)
  end

  it "should return a hash of extracted certificates from OCSP requests" do
    result = @ocsp_handler.extract_certificate_serials
    expect(result.size).to eq(1)
  end

  it "should be able to generate an OCSP response" do
    @ocsp_handler.extract_certificate_serials
    @ocsp_handler << @certificate
    @ocsp_handler.parent = @root_certificate
    @ocsp_handler.response
  end

  it "should require a 'parent' entity for signing" do
    @ocsp_handler.parent = @root_certificate
    expect(@ocsp_handler.parent).not_to be_nil
  end

  it "should raise an error if you ask for the signed OCSP response without generating it" do
    @ocsp_handler.extract_certificate_serials
    @ocsp_handler << @certificate
    @ocsp_handler.parent = @root_certificate
    expect { @ocsp_handler.to_der }.to raise_error(RuntimeError)
    @ocsp_handler.response
    expect(@ocsp_handler.to_der).not_to be_nil
  end

  it "should raise an error if you generate a response without adding all certificates in request" do
    @ocsp_handler.extract_certificate_serials
    @ocsp_handler.parent = @root_certificate
    expect { @ocsp_handler.response }.to raise_error(RuntimeError)
  end

  it "should raise an error if you generate a response without adding a parent signing entity" do
    @ocsp_handler.extract_certificate_serials
    @ocsp_handler << @certificate
    expect { @ocsp_handler.response }.to raise_error(RuntimeError)
  end

  describe "Response" do
    before(:each) do
      @ocsp_handler.extract_certificate_serials
      @ocsp_handler << @certificate
      @ocsp_handler.parent = @root_certificate
      @ocsp_handler.response

      @openssl_ocsp_response = OpenSSL::OCSP::Response.new(@ocsp_handler.to_der)
    end

    it "should have a correct status/status string" do
      expect(@openssl_ocsp_response.status_string).to eq("successful")
      expect(@openssl_ocsp_response.status).to eq(0)
    end

    it "should have an embedded BasicResponse with certificate statuses" do
      # [#<OpenSSL::OCSP::CertificateId:0x000001020ecad8>, 0, 1, nil, 2011-04-15 23:29:47 UTC, 2011-04-15 23:30:17 UTC, []]
      expect(@openssl_ocsp_response.basic.status.first[1]).to eq(0) # Everything is OK
    end

    it "should have a next_update time" do
      expect(@openssl_ocsp_response.basic.status.first[5]).not_to be_nil
      expect(@openssl_ocsp_response.basic.status.first[5].class).to eq(Time)
    end
  end
end
