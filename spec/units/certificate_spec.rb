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
      @certificate.is_signing_entity?.should be_true
      @certificate.signing_entity = false
      @certificate.is_signing_entity?.should be_false
    end
    
    describe "Root certificates" do
      it "should be able to be identified as a root certificate" do
        @certificate.is_root_entity?.should be_true
      end
      
      it "should only be a root certificate if the parent entity is itself" do
        @certificate.parent.should == @certificate
      end
      
      it "should be a root certificate by default" do
        @certificate.is_root_entity?.should be_true
      end
    end
    
    describe "Intermediate certificates" do
      before(:each) do
        @different_cert = CertificateAuthority::Certificate.new
        @certificate.parent = @different_cert
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
    end

    it "should be able to be identified as a root certificate" do
      @certificate.is_root_entity?.should be_true
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
  
end