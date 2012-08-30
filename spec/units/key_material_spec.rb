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
    common_request = <<CSR
-----BEGIN CERTIFICATE REQUEST-----
MIICzzCCAbcCAQAwgYkxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhhczESMBAG
A1UEBwwJQXJsaW5ndG9uMQwwCgYDVQQKDANCYWgxCzAJBgNVBAsMAk5vMRswGQYD
VQQDDBJwemVyby5ib3VneW1hbi5jb20xHjAcBgkqhkiG9w0BCQEWD3RqQHJ1Ynlp
c3RzLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL+UD2trMNFh
lR3utCWBO3i9/VVdz13OnsSrmrnKvVeB6wRUd1gtxJ6sTi70ywN1vJqC3OuiO53G
CPzqWDsaVhQy7wTYCY+6uRfI23pcZZG/sGOHVJAJw+zadyd5LDqh3khsaZHBx1VK
ZiRee09QAnN4kK1uxB5B1ZCE01GzS9ERck7thwlcH2mDMuUtMxXmtEcl8sSeCkZO
CJ9TH21Q90oryZH14+fkhIjDTmyXAtj7kOjyAEu6aD+kYd03Yk+5XWJUVdpuug9Y
ZX7oMd8dzg9wiWzveKWypQ23BxcUS9ejiZVhj0TE0UPAKIhTw/0QkWoNcHOkwh29
X4fdAFIR3gkCAwEAAaAAMA0GCSqGSIb3DQEBBQUAA4IBAQAqlbx13HtfXFJf2boC
IcGrjaY+rOh9rNrXiGN9+DCZciQhEi8ZpOdygwZ4oKE/QjnPX+Q2sm/xjyhqp62v
NZsIGR8jnu1L7c5Jik72W/E2Jz6WLb/dWcGn45pSgi1HvRm+SXTWCIpZYfUrA+A/
x1x4CgU+tBFXtgMGTbK6F+JoaGsBeBkYG95pYurgS9mo62r0Mau3qi68DFzcXCuR
IibGCcF9hys7LbqLLDob6i1Y9TQtw5f6ARE4SkA9TvWM3VPDxn6F+Qfg8TAj7r1q
vecFC7r3d0ySWkdsy+Snzvt0ruu5pOfaTRBQqrIKVeGpOIp7sOhBlExtl/unHkCZ
IpZl
-----END CERTIFICATE REQUEST-----
CSR
    @openssl_req = OpenSSL::X509::Request.new common_request
    @certificate = CertificateAuthority::Certificate.new
    @certificate.serial_number.number = 1
    @certificate.subject.common_name = "chrischandler.name"
    @certificate.key_material.generate_key(1024)
    @certificate.sign!
    @key_material = CertificateAuthority::SigningRequestKeyMaterial.new @request
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
    invalid = @request
    invalid.public_key = OpenSSL::PKey::RSA.new 512
    lambda { CertificateAuthority::SigningRequestKeyMaterial.new invalid }.should raise_error
  end

  it "should only accept valid OpenSSL requests" do
    lambda { CertificateAuthority::SigningRequestKeyMaterial.new OpenSSL::X509::Request.new }.should raise_error(OpenSSL::X509::RequestError)
    req = CertificateAuthority::SigningRequestKeyMaterial.new @openssl_req
    req.csr.subject.should_not be_nil
  end

  it "should add a cert when signed by a root ca" do
    csr = CertificateAuthority::SigningRequestKeyMaterial.new @openssl_req
    signed_cert = csr.sign_and_certify(@certificate, @certificate.key_material.private_key, 555)
    signed_cert.should_not be_nil
    signed_cert.subject.to_x509_name.to_s.should == "/CN=pzero.bougyman.com/O=Bah/OU=No/ST=Texas/L=Arlington/C=US"
  end

  it "can sign an SPKAC SPKI and generate a certificate" do
    spkac_raw = <<SPKAC
MIICQDCCASgwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDVDEqzj21++aMWvN6zzwDXKKpR9g5hIeAPYqbUdaPFePhtz7R73l7fVxDeQZDQpQxTqts0/w0wEa/A1ehHCtAkDoTYzjwX8G0Gkb90poA156I8b4Cl1Q2veKbLsaOsMWItlXSU6HULQ5McfYfvEaPmIKiIr0UIFdzMDcy9TnY854w9TcQVvLJZcQkaM3dy/p9W4gg0a9hBJwwFUUR2UV/nEEi+++HbsOE46Z7Y3qoQhLrL4DNUrXUPDVeqac1SmNfKTA71QADbezWDfKi9habHHGXqk18i2Pl6uA2mpNPuSWnEHbQONgnfeoWZBvMWkwlolaBeWhGSmgcL/HqaRLlFAgMBAAEWADANBgkqhkiG9w0BAQQFAAOCAQEAp8wOvrl2QG9p1PS19dnrh4l0JWNAPB+d1kc64xUG6FAfGCKnOHzdDndTJfEERhWqFA0XL+mvKXCQsYKXkOuxYYmxJXZsdcCj7mOMhI2uMrEVd1ALFmG5WBW1Mo3nHHa/BX24fAOLv0+aGXYTz3oaMFydBw+XPZ26x9pO9LjlQQYGGyQRMpceWfej367KnR4a7IafDGBUI6OoWsx/7kQRIGkbmzi+dnU7HgpEExyz+uuxlUxrZqa13Ys8dBp62NBJWFanPl+AhMe8g/Li5aiERrMUbFtiXzOp48Si7J54fs+U3w0WoD9cdG5mN2Rn8Jog8azl+YC/XY987YGAi7Y8EQ==
SPKAC
    spkac = OpenSSL::Netscape::SPKI.new spkac_raw
    dn = CertificateAuthority::DistinguishedName.new
    dn.common_name = "chrischandler.name"
    csr = CertificateAuthority::SigningRequestKeyMaterial.new spkac
    lambda { csr.sign_and_certify(@certificate, @certificate.key_material.private_key, 554) }.should raise_error(RuntimeError)
    signed_cert = csr.sign_and_certify(@certificate, @certificate.key_material.private_key, 555, :dn => dn)
    signed_cert.should_not be_nil
    signed_cert.subject.to_x509_name.to_s.should == "/CN=chrischandler.name"
  end

end
