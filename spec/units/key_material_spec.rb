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

  ## Anything that requires crypto hardware needs to be tagged as 'pkcs11'
  describe "in hardware", :pkcs11 => true do
    before(:each) do
      @key_material_in_hardware = CertificateAuthority::Pkcs11KeyMaterial.new
      @key_material_in_hardware.token_id = "46"
      @key_material_in_hardware.pkcs11_lib = "/usr/lib/libeTPkcs11.so"
      @key_material_in_hardware.openssl_pkcs11_engine_lib = "/usr/lib/engines/engine_pkcs11.so"
      @key_material_in_hardware.pin = "11111111"
    end

    it "should identify as being in hardware", :pkcs11 => true do
      @key_material_in_hardware.is_in_hardware?.should be_true
    end

    it "should return a Pkey ref if the private key is requested", :pkcs11 => true do
      @key_material_in_hardware.private_key.class.should == OpenSSL::PKey::RSA
    end

    it "should return a Pkey ref if the private key is requested", :pkcs11 => true do
      @key_material_in_hardware.public_key.class.should == OpenSSL::PKey::RSA
    end

    it "should accept an ID for on-token objects", :pkcs11 => true do
      @key_material_in_hardware.respond_to?(:token_id).should be_true
    end

    it "should accept a path to a shared library for a PKCS11 driver", :pkcs11 => true do
      @key_material_in_hardware.respond_to?(:pkcs11_lib).should be_true
    end

    it "should accept a path to OpenSSL's dynamic PKCS11 engine (provided by libengine-pkcs11-openssl)", :pkcs11 => true do
      @key_material_in_hardware.respond_to?(:openssl_pkcs11_engine_lib).should be_true
    end

    it "should accept an optional PIN to authenticate to the token", :pkcs11 => true do
      @key_material_in_hardware.respond_to?(:pin).should be_true
    end

  end

  it "not validate without public and private keys" do
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
