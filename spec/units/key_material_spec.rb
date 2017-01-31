require File.dirname(__FILE__) + '/units_helper'

describe CertificateAuthority::KeyMaterial do
  [CertificateAuthority::MemoryKeyMaterial, CertificateAuthority::SigningRequestKeyMaterial].each do |key_material_class|
    before do
      @key_material = key_material_class.new
    end

    it "#{key_material_class} should know if a key is in memory or hardware" do
      expect(@key_material.is_in_hardware?).not_to be_nil
      expect(@key_material.is_in_memory?).not_to be_nil
    end

    it "should use memory by default" do
      expect(@key_material.is_in_memory?).to be_truthy
    end
  end

  describe "reading keys from PEM" do
    before(:each) do
      @key_pair=<<EOF
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCxiGVfRrf90CHmvXa+XYWE4m7LZ1slc6cxIYyIgZuQ5T8AeqUa
kbyYY4wMUR2gZ4pDPs/WGs8fW66q23qmHSr1bQ6HaL8znbD7UL/IiiyiW8I11orb
rhimIx1A606qi8/0gQc+H851gzUusd5xgKP2X+oPxYx3VG3dpksLnNK1IwIDAQAB
AoGAfrNNRbX+0dGcoERPXoT4KWJAmEHnNs9XXyUGWtXE5J/3Wqws8M1Zv5gr9w5d
CoFal6tYQQFZGJQiECYbXjoq0VT8ApWfuO/mCXyXfmnLFEU8EJjmXtXzn2yyPfoY
At7O8QwvG0bwtw1SqNf7cRtlOEIqoLMtdyaVv4C5ffyheIECQQDVdVf2Sk113Kke
PREzEb6XZ0n2ugSG8fWJh2QKUI4RXhg7bDzHhSpexeKsJdoet8NJOUEsXMoqLSzK
bBnSD63RAkEA1OogtDCkpwkvqC63a7hyDP7qRVHFuVeSA1fu+6BFS0xblkgvcPXT
J7WbWYcP+lqcLjXWeFsqe5qS6sDCsAhsswJAIumZZHgMqU1Y/9AfIwow8RR8vXT5
TpT+gur5CtLYGbEZJ4bxffSi1HNrOprKTSHjN/O8XCQlELboz4bUxk24MQJAcsaX
xKsoR4dTMoWkiSRQDyNoJOA1B3nmk3jWsryuPi42fSgCsxFBt/lVeoitm1c3NE3/
hLgYibNFGdm52e1gswJBAMwYuImbl6AVLv0Y41smxIkvfAzlyNfTAsp7GqLoMhYN
q/0KoyI2Ge3+NnmJI/eaiYs8qC2HjrgdX9ZDSUCWfpQ=
-----END RSA PRIVATE KEY-----
EOF
    @public_key=<<EOF
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCxiGVfRrf90CHmvXa+XYWE4m7L
Z1slc6cxIYyIgZuQ5T8AeqUakbyYY4wMUR2gZ4pDPs/WGs8fW66q23qmHSr1bQ6H
aL8znbD7UL/IiiyiW8I11orbrhimIx1A606qi8/0gQc+H851gzUusd5xgKP2X+oP
xYx3VG3dpksLnNK1IwIDAQAB
-----END PUBLIC KEY-----
EOF

      @encrypted_key_pair=<<EOF
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,EF5CCB3A64C0A6DB57FB924A3ED5B9A6

qziIbWkeBVYS8Lhs3DqW6BeL6/rLDOyLcei604qx/SsmQZfNPb6SfRnq5EWqWk8V
kHHA9cPb8x8bRNdGiajg4NPwXHlkEBUJkeM8C24MCvPEztM7jooPtmrRR8ilz3m+
62LyvyzO6LIHonoqOq/jQwfYFOInPTqpwW/drzkFxuh2Mc7enVnU9e+Z5Pnk6I8g
Sv7Nmh1kMEArzu4vSFBFalBFJkFOXjysOUMhQ7SJwKHmTbKEqcI5Le5NKT708BMa
xnDzWQQgvKjiOSKz71Gq2QT3hwqV1bgwV015G0xlpWpBhemey4pr6L3AxysWFujO
z1fHe0MaV6dbQNwymljwdE5R+9jzU8uEmdo8QrrRnzUnetr01uUcWgOUqnKmuinq
WMl7Odvep6hoBbqSMfESJZJA9+XPBXfs4FHE1Ri8riAPoGLl484Lj91cVqBqVXZG
tht39kXNYROOqBZ7pU9fNuTFhDHvAoH9ydFD6YpTRZALHTgSdyZ5IbhmOiJAlW3b
nhAZtMwwcTYJIF8xyR+8GAdAG/dIDFM+tRmeB1aRkSd6IgxLMh52SFv/vSglEwYj
PYHvhcpId93yYO34vCGT4tGsZ2j2VpZqAyu5cl8K6Hq8dTYzH2jkfSdGQ9a8vCKG
jSlK4vK91ZFdO8sTCTlQd6+jUXH3B4wTUsA4key7yUGLXMr1jmapRQJIuhCUnQQn
B9Py5RdGlGW2ycVaGh08n4LmG/OTJuLb+xTStm5w4iLmB+ynDjIxpfQjvX98hzMh
G35pgQ2GdKs+NByYXZKz0OHT2NAHkKpoO7rPlzTpMLgUtAGmH7rLEeOUz6TscUDc
-----END RSA PRIVATE KEY-----
EOF
    end

    it "should include a means of reading an RSA keypair" do
      key = CertificateAuthority::KeyMaterial.from_x509_key_pair(@key_pair)
      expect(key.public_key).not_to be_nil
      expect(key.public_key).to be_a(OpenSSL::PKey::RSA)
      expect(key.private_key).not_to be_nil
      expect(key.private_key).to be_a(OpenSSL::PKey::RSA)
    end

    it "should include a means of reading encrypted RSA keypairs" do
      key = CertificateAuthority::KeyMaterial.from_x509_key_pair(@encrypted_key_pair,"meow")
      expect(key.public_key).not_to be_nil
      expect(key.public_key).to be_a(OpenSSL::PKey::RSA)
      expect(key.private_key).not_to be_nil
      expect(key.private_key).to be_a(OpenSSL::PKey::RSA)
    end

    it "should raise an exception if you read an encrypted keypair w/ bad password" do
      expect {
        key = CertificateAuthority::KeyMaterial.from_x509_key_pair(@encrypted_key_pair,"wrong")
      }.to raise_error(OpenSSL::PKey::RSAError)
    end

    it "should include a means of reading a public-only PEM formatted key" do
      key = CertificateAuthority::KeyMaterial.from_x509_public_key(@public_key)
      expect(key.public_key).not_to be_nil
      expect(key.public_key).to be_a(OpenSSL::PKey::RSA)
    end
  end
end

describe CertificateAuthority::MemoryKeyMaterial do
  before(:each) do
    @key_material = CertificateAuthority::MemoryKeyMaterial.new
  end

  it "should be able to generate an RSA key" do
    expect(@key_material.generate_key(768)).not_to be_nil
  end

  it "should generate a proper OpenSSL::PKey::RSA" do
    expect(@key_material.generate_key(768).class).to eq(OpenSSL::PKey::RSA)
  end

  it "should be able to specify the size of the modulus to generate" do
    expect(@key_material.generate_key(768)).not_to be_nil
  end

  describe "with generated key" do
    before(:all) do
      @key_material_in_memory = CertificateAuthority::MemoryKeyMaterial.new
      @key_material_in_memory.generate_key(768)
    end

    it "should be able to retrieve the private key" do
      expect(@key_material_in_memory.private_key).not_to be_nil
    end

    it "should be able to retrieve the public key" do
      expect(@key_material_in_memory.public_key).not_to be_nil
    end
  end

  it "should not validate without public and private keys" do
    expect(@key_material.valid?).to be_falsey
    @key_material.generate_key(768)
    expect(@key_material.valid?).to be_truthy
    pub = @key_material.public_key
    @key_material.public_key = nil
    expect(@key_material.valid?).to be_falsey
    @key_material.public_key = pub
    @key_material.private_key = nil
    expect(@key_material.valid?).to be_falsey
  end
end

describe CertificateAuthority::SigningRequestKeyMaterial do
  before(:each) do
    @request = OpenSSL::X509::Request.new <<CSR
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
    @key_material = CertificateAuthority::SigningRequestKeyMaterial.new @request
  end

  it "should generate from a CSR" do
    expect(@key_material).not_to be_nil
  end

  it "should be able to expose a public key" do
    expect(@key_material.public_key).not_to be_nil
  end

  it "should not have a private key" do
    expect(@key_material.private_key).to be_nil
  end

  it "should raise when signature does not verify" do
    invalid = @request
    invalid.public_key = OpenSSL::PKey::RSA.new 512
    expect { CertificateAuthority::SigningRequestKeyMaterial.new invalid }.to raise_error(RuntimeError)
  end
end
