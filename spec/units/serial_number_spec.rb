require File.dirname(__FILE__) + '/units_helper'

describe CertificateAuthority::SerialNumber do
  before(:each) do
    @serial_number = CertificateAuthority::SerialNumber.new
  end

  it "should support basic integer serial numbers", :rfc3280 => true do
    @serial_number.number = 25
    expect(@serial_number).to be_valid
    @serial_number.number = "abc"
    expect(@serial_number).not_to be_valid
  end

  it "should not allow negative serial numbers", :rfc3280 => true do
    @serial_number.number = -5
    expect(@serial_number).not_to be_valid
  end

end
