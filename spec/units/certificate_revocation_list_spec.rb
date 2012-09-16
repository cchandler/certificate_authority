require File.dirname(__FILE__) + '/units_helper'

describe CertificateAuthority::CertificateRevocationList do
  before(:each) do
    @crl = CertificateAuthority::CertificateRevocationList.new

    @root_certificate = CertificateAuthority::Certificate.new
    @root_certificate.signing_entity = true
    @root_certificate.subject.common_name = "CRL Root"
    @root_certificate.key_material.generate_key(768)
    @root_certificate.serial_number.number = 1
    @root_certificate.sign!

    @certificate = CertificateAuthority::Certificate.new
    @certificate.key_material.generate_key(768)
    @certificate.subject.common_name = "http://bogusSite.com"
    @certificate.parent = @root_certificate
    @certificate.serial_number.number = 2
    @certificate.sign!

    @serial_number = CertificateAuthority::SerialNumber.new
    @serial_number.revoked_at = Time.now
    @serial_number.number = 5

    @crl.parent = @root_certificate
    @certificate.revoked_at = Time.now
  end

  it "should accept a list of certificates" do
    @crl << @certificate
  end

  it "should complain if you add a certificate without a revocation time" do
    @certificate.revoked_at = nil
    lambda{ @crl << @certificate}.should raise_error
  end

  it "should have a 'parent' that will be responsible for signing" do
    @crl.parent = @root_certificate
    @crl.parent.should_not be_nil
  end

  it "should raise an error if you try and sign a CRL without attaching a parent" do
    @crl.parent = nil
    lambda { @crl.sign! }.should raise_error
  end

  it "should be able to generate a proper CRL" do
    @crl << @certificate
    lambda {@crl.to_pem}.should raise_error
    @crl.parent = @root_certificate
    @crl.sign!
    @crl.to_pem.should_not be_nil
    OpenSSL::X509::CRL.new(@crl.to_pem).should_not be_nil
  end

  it "should be able to mix Certificates and SerialNumbers for convenience" do
    @crl << @certificate
    @crl << @serial_number
    @crl.parent = @root_certificate
    @crl.sign!
    openssl_csr = OpenSSL::X509::CRL.new(@crl.to_pem)
    openssl_csr.revoked.size.should == 2
  end

  it "should have the correct number of entities" do
    @crl << @certificate
    @crl.parent = @root_certificate
    @crl.sign!
    openssl_clr = OpenSSL::X509::CRL.new(@crl.to_pem)
    openssl_clr.revoked.should be_a(Array)
    openssl_clr.revoked.size.should == 1
  end

  it "should have the serial numbers of revoked entities" do
    @crl << @certificate
    @crl << @serial_number
    @crl.parent = @root_certificate
    @crl.sign!
    openssl_clr = OpenSSL::X509::CRL.new(@crl.to_pem)
    openssl_clr.revoked.should be_a(Array)
    openssl_clr.revoked.first.serial.should == @certificate.serial_number.number
    openssl_clr.revoked.last.serial.should == @serial_number.number
  end

  it "should be valid according to OpenSSL and signer" do
    @crl << @certificate
    @crl.parent = @root_certificate
    @crl.sign!
    openssl_clr = OpenSSL::X509::CRL.new(@crl.to_pem)
    openssl_root = OpenSSL::X509::Certificate.new(@root_certificate.to_pem)
    openssl_clr.verify(openssl_root.public_key).should be_true
  end

  describe "Digests" do
    it "should use SHA512 by default" do
      @crl << @certificate
      @crl.parent = @root_certificate
      @crl.sign!
      openssl_clr = OpenSSL::X509::CRL.new(@crl.to_pem)
      openssl_clr.signature_algorithm.should == "sha512WithRSAEncryption"
    end

    it "should support alternate digests supported by OpenSSL" do
      @crl << @certificate
      @crl.parent = @root_certificate
      @crl.sign!({"digest" => "SHA1"})
      openssl_clr = OpenSSL::X509::CRL.new(@crl.to_pem)
      openssl_clr.signature_algorithm.should == "sha1WithRSAEncryption"
    end
  end

  describe "Next update" do
    it "should be able to set a 'next_update' value" do
      @crl.next_update = (60 * 60 * 10) # 10 Hours
      @crl.next_update.should_not be_nil
    end

    it "should throw an error if we try and sign up with a negative next_update" do
      @crl.sign!
      @crl.next_update = - (60 * 60 * 10)
      lambda{@crl.sign!}.should raise_error
    end
  end
end
