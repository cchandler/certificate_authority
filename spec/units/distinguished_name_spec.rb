require File.dirname(__FILE__) + '/units_helper'

describe CertificateAuthority::DistinguishedName do
  before(:each) do
    @distinguished_name = CertificateAuthority::DistinguishedName.new
  end

  it "should provide the standard x.509 distinguished name common attributes" do
    expect(@distinguished_name.respond_to?(:cn)).to be_truthy
    expect(@distinguished_name.respond_to?(:l)).to be_truthy
    expect(@distinguished_name.respond_to?(:s)).to be_truthy
    expect(@distinguished_name.respond_to?(:o)).to be_truthy
    expect(@distinguished_name.respond_to?(:ou)).to be_truthy
    expect(@distinguished_name.respond_to?(:c)).to be_truthy
    expect(@distinguished_name.respond_to?(:emailAddress)).to be_truthy
    expect(@distinguished_name.respond_to?(:serialNumber)).to be_truthy
  end

  it "should provide human-readable equivalents to the distinguished name common attributes" do
    expect(@distinguished_name.respond_to?(:common_name)).to be_truthy
    expect(@distinguished_name.respond_to?(:locality)).to be_truthy
    expect(@distinguished_name.respond_to?(:state)).to be_truthy
    expect(@distinguished_name.respond_to?(:organization)).to be_truthy
    expect(@distinguished_name.respond_to?(:organizational_unit)).to be_truthy
    expect(@distinguished_name.respond_to?(:country)).to be_truthy
    expect(@distinguished_name.respond_to?(:email_address)).to be_truthy
    expect(@distinguished_name.respond_to?(:serial_number)).to be_truthy
  end

  it "should require a common name" do
    expect(@distinguished_name.valid?).to be_falsey
    expect(@distinguished_name.errors.size).to eq(1)
    @distinguished_name.common_name = "chrischandler.name"
    expect(@distinguished_name.valid?).to be_truthy
  end

  it "should be convertible to an OpenSSL::X509::Name" do
    @distinguished_name.common_name = "chrischandler.name"
    @distinguished_name.to_x509_name
  end

  describe "from_openssl" do
    before do
      subject = "/CN=justincummins.name/L=on my laptop/ST=relaxed/C=as/O=programmer/OU=using this code"
      @name = OpenSSL::X509::Name.parse subject
      @dn = CertificateAuthority::DistinguishedName.from_openssl @name
    end

    it "should reject non Name objects" do
      expect { CertificateAuthority::DistinguishedName.from_openssl "Not a OpenSSL::X509::Name" }.to raise_error(RuntimeError)
    end

    [:common_name, :locality, :state, :country, :organization, :organizational_unit].each do |field|
      it "should set the #{field} attribute" do
        expect(@dn.send(field)).not_to be_nil
      end
    end

    it "should create an equivalent object" do
      expect(@dn.to_x509_name.to_s.split('/')).to match_array(@name.to_s.split('/'))
    end

  end

  describe CertificateAuthority::WrappedDistinguishedName do
    it "should mark the DN as having custom OIDs if there's an unknown subject element" do
      OpenSSL::ASN1::ObjectId.register("2.3.4.5","testing","testingCustomOIDs")
      subject = "/testingCustomOIDs=custom/CN=justincummins.name/L=on my laptop/ST=relaxed/C=as/O=programmer/OU=using this code"
      @name = OpenSSL::X509::Name.parse subject
      @dn = CertificateAuthority::DistinguishedName.from_openssl @name
      expect(@dn.custom_oids?).to be_truthy
    end
  end
end
