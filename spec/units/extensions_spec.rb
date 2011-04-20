require File.dirname(__FILE__) + '/units_helper'

describe CertificateAuthority::Extensions do
  describe CertificateAuthority::Extensions::BasicContraints do
    it "should only allow true/false" do
      basic_constraints = CertificateAuthority::Extensions::BasicContraints.new
      basic_constraints.valid?.should be_true
      basic_constraints.ca = "moo"
      basic_constraints.valid?.should be_false
    end
    
    it "should respond to :path_len" do
      basic_constraints = CertificateAuthority::Extensions::BasicContraints.new
      basic_constraints.respond_to?(:path_len).should be_true
    end
    
    it "should raise an error if :path_len isn't a non-negative integer" do
      basic_constraints = CertificateAuthority::Extensions::BasicContraints.new
      lambda {basic_constraints.path_len = "moo"}.should raise_error
      lambda {basic_constraints.path_len = -1}.should raise_error
      lambda {basic_constraints.path_len = 1.5}.should raise_error
    end
    
    it "should generate a proper OpenSSL extension string" do
      basic_constraints = CertificateAuthority::Extensions::BasicContraints.new
      basic_constraints.ca = true
      basic_constraints.path_len = 2
      basic_constraints.to_s.should == "CA:true,pathlen:2"
    end
  end
  
  describe CertificateAuthority::Extensions::SubjectAlternativeName do
    it "should respond to :uris" do
      subjectAltName = CertificateAuthority::Extensions::SubjectAlternativeName.new
      subjectAltName.respond_to?(:uris).should be_true
    end
    
    it "should require 'uris' to be an Array" do
      subjectAltName = CertificateAuthority::Extensions::SubjectAlternativeName.new
      lambda {subjectAltName.uris = "not an array"}.should raise_error
    end
    
    it "should generate a proper OpenSSL extension string" do
      subjectAltName = CertificateAuthority::Extensions::SubjectAlternativeName.new
      subjectAltName.uris = ["http://localhost.altname.example.com"]
      subjectAltName.to_s.should == "URI:http://localhost.altname.example.com"
      
      subjectAltName.uris = ["http://localhost.altname.example.com", "http://other.example.com"]
      subjectAltName.to_s.should == "URI:http://localhost.altname.example.com,URI:http://other.example.com"
    end
    
  end
end