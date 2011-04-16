require File.dirname(__FILE__) + '/units_helper'

describe CertificateAuthority::SerialNumber do
  before(:each) do
    @serial_number = CertificateAuthority::SerialNumber.new
  end
  
  it "should support basic integer serial numbers", :rfc3280 => true do
    @serial_number.number = 25
    @serial_number.should be_valid
    @serial_number.number = "abc"
    @serial_number.should_not be_valid
  end
  
  it "should not allow negative serial numbers", :rfc3280 => true do
    @serial_number.number = -5
    @serial_number.should_not be_valid
  end
  
end