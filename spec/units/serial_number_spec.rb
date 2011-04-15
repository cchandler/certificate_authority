require File.dirname(__FILE__) + '/units_helper'

describe CertificateAuthority::SerialNumber do
  before(:each) do
    @serial_number = CertificateAuthority::SerialNumber.new
    @serial_number.number = 25
  end
  
  it "should support basic integer serial numbers" do
    
  end
end