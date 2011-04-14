require File.dirname(__FILE__) + '/units_helper'

describe CertificateAuthority::Extensions do
  describe CertificateAuthority::Extensions::BasicContraints do
    it "should only allow true/false" do
      basic_constraints = CertificateAuthority::Extensions::BasicContraints.new
      basic_constraints.valid?.should be_true
      basic_constraints.ca = "moo"
      basic_constraints.valid?.should be_false
    end
  end
  
end