require File.dirname(__FILE__) + '/units_helper'

describe CertificateAuthority::MemoryKeyMaterial do
  before(:each) do
    @key_material = CertificateAuthority::MemoryKeyMaterial.new
  end

  it "should know if a key is in memory or hardware" do
    @key_material.is_in_hardware?.should_not be_nil
    @key_material.is_in_memory?.should_not be_nil
  end

  it "should use memory by default" do
    @key_material.is_in_memory?.should be_true
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

  describe "in memory" do
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