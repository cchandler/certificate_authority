require File.dirname(__FILE__) + '/units_helper'

## Anything that requires crypto hardware needs to be tagged as 'pkcs11'
describe CertificateAuthority::Pkcs11KeyMaterial, :pkcs11 => true do
  before(:each) do
    @key_material_in_hardware = CertificateAuthority::Pkcs11KeyMaterial.new
    @key_material_in_hardware.token_id = "46"
    @key_material_in_hardware.pkcs11_lib = "/usr/lib/libeTPkcs11.so"
    @key_material_in_hardware.openssl_pkcs11_engine_lib = "/usr/lib/engines/engine_pkcs11.so"
    @key_material_in_hardware.pin = "11111111"
  end

  it "should identify as being in hardware", :pkcs11 => true do
    expect(@key_material_in_hardware.is_in_hardware?).to be_truthy
  end

  it "should return a Pkey ref if the private key is requested", :pkcs11 => true do
    expect(@key_material_in_hardware.private_key.class).to eq(OpenSSL::PKey::RSA)
  end

  it "should return a Pkey ref if the public key is requested", :pkcs11 => true do
    expect(@key_material_in_hardware.public_key.class).to eq(OpenSSL::PKey::RSA)
  end

  it "should accept an ID for on-token objects", :pkcs11 => true do
    expect(@key_material_in_hardware.respond_to?(:token_id)).to be_truthy
  end

  it "should accept a path to a shared library for a PKCS11 driver", :pkcs11 => true do
    expect(@key_material_in_hardware.respond_to?(:pkcs11_lib)).to be_truthy
  end

  it "should accept a path to OpenSSL's dynamic PKCS11 engine (provided by libengine-pkcs11-openssl)", :pkcs11 => true do
    expect(@key_material_in_hardware.respond_to?(:openssl_pkcs11_engine_lib)).to be_truthy
  end

  it "should accept an optional PIN to authenticate to the token", :pkcs11 => true do
    expect(@key_material_in_hardware.respond_to?(:pin)).to be_truthy
  end

end
