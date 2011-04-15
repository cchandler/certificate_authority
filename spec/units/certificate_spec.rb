require File.dirname(__FILE__) + '/units_helper'

describe CertificateAuthority::Certificate do
  before(:each) do
    @certificate = CertificateAuthority::Certificate.new
  end
  
  describe CertificateAuthority::SigningEntity do
    it "should behave as a signing entity" do
      @certificate.respond_to?(:is_signing_entity?).should be_true
    end
    
    it "should only be a signing entity if it's identified as a CA" do
      @certificate.is_signing_entity?.should be_false
      @certificate.signing_entity = true
      @certificate.is_signing_entity?.should be_true
    end
    
    describe "Root certificates" do
      before(:each) do
        @certificate.signing_entity = true
      end
      
      it "should be able to be identified as a root certificate" do
        @certificate.is_root_entity?.should be_true
      end
      
      it "should only be a root certificate if the parent entity is itself" do
        @certificate.parent.should == @certificate
      end
      
      it "should be a root certificate by default" do
        @certificate.is_root_entity?.should be_true
      end
      
      it "should be able to self-sign" do
        @certificate.serial_number.number = 1
        @certificate.subject.common_name = "chrischandler.name"
        @certificate.key_material.generate_key
        @certificate.sign!
        cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
        cert.subject.to_s.should == cert.issuer.to_s
      end
      
      it "should have the basicContraint CA:TRUE" do
        @certificate.serial_number.number = 1
        @certificate.subject.common_name = "chrischandler.name"
        @certificate.key_material.generate_key
        @certificate.sign!
        cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
        cert.extensions.first.value.should == "CA:TRUE"
      end
    end
    
    describe "Intermediate certificates" do
      before(:each) do
        @different_cert = CertificateAuthority::Certificate.new
        @different_cert.signing_entity = true
        @different_cert.subject.common_name = "chrischandler.name root"
        @different_cert.key_material.generate_key
        @different_cert.serial_number.number = 2
        @different_cert.sign! #self-signed
        @certificate.parent = @different_cert
        @certificate.signing_entity = true
      end
      
      it "should be able to be identified as an intermediate certificate" do
        @certificate.is_intermediate_entity?.should be_true
      end
      
      it "should not be identified as a root" do
        @certificate.is_root_entity?.should be_false
      end
      
      it "should only be an intermediate certificate if the parent is a different entity" do
        @certificate.parent.should_not == @certificate
        @certificate.parent.should_not be_nil
      end
      
      it "should correctly be signed by a parent certificate" do
        @certificate.subject.common_name = "chrischandler.name"
        @certificate.key_material.generate_key
        @certificate.signing_entity = true
        @certificate.serial_number.number = 1
        @certificate.sign!
        cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
        cert.subject.to_s.should_not == cert.issuer.to_s
      end
      
      it "should have the basicContraint CA:TRUE" do
        @certificate.subject.common_name = "chrischandler.name"
        @certificate.key_material.generate_key
        @certificate.signing_entity = true
        @certificate.serial_number.number = 3
        @certificate.sign!
        cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
        cert.extensions.first.value.should == "CA:TRUE"
      end
      
    end
    
    describe "Terminal certificates" do
      before(:each) do
        @different_cert = CertificateAuthority::Certificate.new
        @different_cert.signing_entity = true
        @different_cert.subject.common_name = "chrischandler.name root"
        @different_cert.key_material.generate_key
        @different_cert.serial_number.number = 1
        @different_cert.sign! #self-signed
        @certificate.parent = @different_cert
      end
      
      it "should not be identified as an intermediate certificate" do
        @certificate.is_intermediate_entity?.should be_false
      end
      
      it "should not be identified as a root" do
        @certificate.is_root_entity?.should be_false
      end
      
      it "should have the basicContraint CA:FALSE" do
        @certificate.subject.common_name = "chrischandler.name"
        @certificate.key_material.generate_key
        @certificate.signing_entity = false
        @certificate.serial_number.number = 1
        @certificate.sign!
        cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
        cert.extensions.first.value.should == "CA:FALSE"
      end
    end
    

    it "should be able to be identified as a root certificate" do
      @certificate.is_root_entity?.should be_true
    end
  end #End of SigningEntity
  
  describe "Signed certificates" do
    before(:each) do
      @certificate = CertificateAuthority::Certificate.new
      @certificate.subject.common_name = "chrischandler.name"
      @certificate.key_material.generate_key
      @certificate.serial_number.number = 1
      @certificate.sign!
    end
    
    it "should have a PEM encoded certificate body available" do
      @certificate.to_pem.should_not be_nil
      OpenSSL::X509::Certificate.new(@certificate.to_pem).should_not be_nil
    end
  end
  
  describe "X.509 V3 Extensions on Signed Certificates" do
    before(:each) do
      @certificate = CertificateAuthority::Certificate.new
      @certificate.subject.common_name = "chrischandler.name"
      @certificate.key_material.generate_key
      @certificate.serial_number.number = 1
      @certificate.sign!
    end
    
    it "should support BasicContraints" do
      cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
      cert.extensions.map(&:oid).include?("basicConstraints").should be_true
    end
    
    it "should support crlDistributionPoints" do
      cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
      cert.extensions.map(&:oid).include?("crlDistributionPoints").should be_true
    end
    
    it "should support subjectKeyIdentifier" do
      cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
      cert.extensions.map(&:oid).include?("subjectKeyIdentifier").should be_true
    end
    
    it "should support authorityKeyIdentifier" do
      cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
      cert.extensions.map(&:oid).include?("authorityKeyIdentifier").should be_true
    end
    
    it "should support authorityInfoAccess" do
      cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
      cert.extensions.map(&:oid).include?("authorityInfoAccess").should be_true
    end
    
    it "should support keyUsage" do
      cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
      cert.extensions.map(&:oid).include?("keyUsage").should be_true
    end
    
    it "should support extendedKeyUsage" do
      cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
      cert.extensions.map(&:oid).include?("extendedKeyUsage").should be_true
    end
    
    it "should support subjectAlternativeName" do
      cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
      cert.extensions.map(&:oid).include?("subjectAltName").should be_true
    end
  end
  
  
  it "should have a distinguished name" do
    @certificate.distinguished_name.should_not be_nil
  end
  
  it "should have a serial number" do
    @certificate.serial_number.should_not be_nil
  end
  
  it "should have a subject" do
    @certificate.subject.should_not be_nil
  end
  
  it "should be able to have a parent entity" do
    @certificate.respond_to?(:parent).should be_true
  end
  
  it "should have key material" do
    @certificate.key_material.should_not be_nil
  end
  
  it "should have a not_before field" do
    @certificate.not_before.should_not be_nil
  end
  
  it "should have a not_after field" do
    @certificate.not_after.should_not be_nil
  end
  
  it "should default to one year validity" do
    @certificate.not_after.should < Time.now + 65 * 60 * 24 * 365 and
    @certificate.not_after.should > Time.now + 55 * 60 * 24 * 365
  end
  
  it "should be able to have a revoked at time" do
    @certificate.revoked?.should be_false
    @certificate.revoked_at = Time.now
    @certificate.revoked?.should be_true
  end
  
end