require File.dirname(__FILE__) + '/units_helper'

describe CertificateAuthority::KeyMaterial do
  [CertificateAuthority::MemoryKeyMaterial, CertificateAuthority::SigningRequestKeyMaterial].each do |key_material_class|
    before do
      @key_material = key_material_class.new
    end

    it "#{key_material_class} should know if a key is in memory or hardware" do
      @key_material.is_in_hardware?.should_not be_nil
      @key_material.is_in_memory?.should_not be_nil
    end

    it "should use memory by default" do
      @key_material.is_in_memory?.should be_true
    end
  end
end

describe CertificateAuthority::MemoryKeyMaterial do
  before(:each) do
    @key_material = CertificateAuthority::MemoryKeyMaterial.new
  end

  it "should be able to generate an RSA key" do
    @key_material.generate_key(1024).should_not be_nil
  end

  it "should generate a proper OpenSSL::PKey::RSA" do
    @key_material.generate_key(1024).class.should == OpenSSL::PKey::RSA
  end

  it "should be able to specify the size of the modulus to generate" do
    @key_material.generate_key(1024).should_not be_nil
  end

  describe "with generated key" do
    before(:all) do
      @key_material_in_memory = CertificateAuthority::MemoryKeyMaterial.new
      @key_material_in_memory.generate_key(1024)
    end

    it "should be able to retrieve the private key" do
      @key_material_in_memory.private_key.should_not be_nil
    end

    it "should be able to retrieve the public key" do
      @key_material_in_memory.public_key.should_not be_nil
    end
  end

  it "should not validate without public and private keys" do
    @key_material.valid?.should be_false
    @key_material.generate_key(1024)
    @key_material.valid?.should be_true
    pub = @key_material.public_key
    @key_material.public_key = nil
    @key_material.valid?.should be_false
    @key_material.public_key = pub
    @key_material.private_key = nil
    @key_material.valid?.should be_false
  end
end

describe CertificateAuthority::SigningRequestKeyMaterial do
  REQUEST = OpenSSL::X509::Request.new <<CSR
-----BEGIN CERTIFICATE REQUEST-----
MIIBjTCB9wIBADBOMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEU
MBIGA1UEBxMLQmVyc2Vya2VsZXkxFDASBgNVBAoTC0NlcnRzICdSIFVzMIGfMA0G
CSqGSIb3DQEBAQUAA4GNADCBiQKBgQCaGiBcv++581KYt6y2NNcUaZNPPeNZ0UkX
ujzZQQllx7PlYmsKTE6ZzfTUc0AJvDBIuACg03eagaEaBZtUFbsLkSOLJyYiIfF5
f9PuXImz2RDzBJQ/+u82gQAcvPhm94xK8jeNPcn0Ege7Y7SRK4YYonX+0ZveP02L
FjuEfrZcZQIDAQABoAAwDQYJKoZIhvcNAQEFBQADgYEAecOQz0RfnmSxxzOyHZ1e
Wo2hQqPOmkfIbvL2l1Ml+HybJQJn6OpLmeveyU48SI2M7UqeNkHtsogMljy3re4L
QlwK7lNd6SymdfSCPjUcdoLOaHolZXYNvCHltTc5skRHG7ti5yv4cu0ItIcCS0yp
7L3maDEbTLsDdouHeFfbLWA=
-----END CERTIFICATE REQUEST-----
CSR

  before(:each) do
    @key_material = CertificateAuthority::SigningRequestKeyMaterial.new REQUEST
  end

  it "should generate from a CSR" do
    @key_material.should_not be_nil
  end

  it "should be able to expose a public key" do
    @key_material.public_key.should_not be_nil
  end

  it "should not have a private key" do
    @key_material.private_key.should be_nil
  end

  it "should raise when signature does not verify" do
    invalid = REQUEST
    invalid.public_key = OpenSSL::PKey::RSA.new 512
    lambda { CertificateAuthority::SigningRequestKeyMaterial.new invalid }.should raise_error
  end
end