require File.dirname(__FILE__) + '/units_helper'

describe CertificateAuthority::DistinguishedName do
  it "should provide the standard x.509 distinguished name common attributes" do
    dn = CertificateAuthority::DistinguishedName.new
    dn.respond_to?(:cn).should be_true
    dn.respond_to?(:l).should be_true
    dn.respond_to?(:s).should be_true
    dn.respond_to?(:o).should be_true
    dn.respond_to?(:ou).should be_true
    dn.respond_to?(:c).should be_true
  end
  
  it "should provide human-readable equivalents to the distinguished name common attributes" do
    dn = CertificateAuthority::DistinguishedName.new
    dn.respond_to?(:common_name).should be_true
    dn.respond_to?(:locality).should be_true
    dn.respond_to?(:state).should be_true
    dn.respond_to?(:organization).should be_true
    dn.respond_to?(:organizational_unit).should be_true
    dn.respond_to?(:country).should be_true
  end
end