require File.dirname(__FILE__) + '/units_helper'

describe CertificateAuthority::DistinguishedName do
  before(:each) do
    @distinguished_name = CertificateAuthority::DistinguishedName.new
  end
  
  it "should provide the standard x.509 distinguished name common attributes" do
    @distinguished_name.respond_to?(:cn).should be_true
    @distinguished_name.respond_to?(:l).should be_true
    @distinguished_name.respond_to?(:s).should be_true
    @distinguished_name.respond_to?(:o).should be_true
    @distinguished_name.respond_to?(:ou).should be_true
    @distinguished_name.respond_to?(:c).should be_true
  end
  
  it "should provide human-readable equivalents to the distinguished name common attributes" do
    @distinguished_name.respond_to?(:common_name).should be_true
    @distinguished_name.respond_to?(:locality).should be_true
    @distinguished_name.respond_to?(:state).should be_true
    @distinguished_name.respond_to?(:organization).should be_true
    @distinguished_name.respond_to?(:organizational_unit).should be_true
    @distinguished_name.respond_to?(:country).should be_true
  end
  
  it "should require a common name" do
    @distinguished_name.valid?.should be_false
    @distinguished_name.errors.size.should == 1
    @distinguished_name.common_name = "chrischandler.name"
    @distinguished_name.valid?.should be_true
  end
  
  it "should be convertible to an OpenSSL::X509::Name" do
    @distinguished_name.common_name = "chrischandler.name"
    @distinguished_name.to_x509_name
  end
  
end