require File.dirname(__FILE__) + '/units_helper'

describe CertificateAuthority::SigningRequest do
  before(:each) do
    @pem_csr =<<EOF
-----BEGIN CERTIFICATE REQUEST-----
MIICwDCCAagCAQAwezELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWEx
FjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xHjAcBgNVBAoTFUNlcnRpZmljYXRlIEF1
dGhvcml0eTEfMB0GA1UEAxMWd3d3LmNocmlzY2hhbmRsZXIubmFtZTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAMCYdPHqyAafolv+tDmCPVj8R11aZSqG
h44W2AF7OOhTYiiyJaudBU4uYryJHeWVMnL2I9uxyvzDqBSfjwIU3bQAAvoqWdlS
qa/V5kLa5CM4nSYvdBErvpxEyd6neAEgtPepPqKWGve8WRziuL0it/TopBTl4eOl
yqHrXTa3I98qBWS28Iifxpz9SXcCaXXHmMmK9KN0Y+BVCJZFVHtPoTLNIxF+nu6S
SieWtGXVe71pDDumndjuYsn3vw+q0Oc8v79AYb0ltdU/lc6ptoSQ5dG0NRG9OA0v
hKntu8TvzgOD6IunJ2ttuLLZ3OqWIwZHi6KrahxOjwoMHVpGdzVLrxkCAwEAAaAA
MA0GCSqGSIb3DQEBBQUAA4IBAQA9Vc/WPbGWieetcaz6uDToFSJZhXyhRKuiMDwJ
cBYWiDlzpNXPTsrWnaDr2kySHpLvlrl3GPpMTvTOO1QYfYmX+adgHmZAwezBsI4a
NBnaAcI4Qv8p+v7ZxHa3yr78Mxj08Yoihd0/f7Ls5XFUppYpwNoYiKYroOMNPEuu
TJC3u6zMEQH8wtHUy3Ii3Ho+MlXlz/DynlOAPmq6EpnMAwh8fMSbMtwTJeVcU34d
m7FwfCvp/120RQLdKaB7zYffcwJUBLTSRKIYkWl9lAC4MlhLUfLmYnJi19Gj/SJZ
jX2pfrub2mscWVhEw+kxYakXh31KnroCYN9I3WGWNYi9ysbi
-----END CERTIFICATE REQUEST-----
EOF
  end

  it "should generate from a PEM CSR" do
    csr = CertificateAuthority::SigningRequest.from_x509_csr(@pem_csr)
    csr.should_not be_nil
    csr.should be_a(CertificateAuthority::SigningRequest)
  end

  it "should generate a proper DN from the CSR" do
    csr = CertificateAuthority::SigningRequest.from_x509_csr(@pem_csr)
    expected_dn = CertificateAuthority::DistinguishedName.new
    expected_dn.country = "US"
    expected_dn.organization = "Certificate Authority"
    expected_dn.common_name = "www.chrischandler.name"
    expected_dn.locality = "San Francisco"
    expected_dn.state = "California"
    csr.distinguished_name.should == expected_dn
  end

  it "should expose the underlying OpenSSL CSR" do
    csr = CertificateAuthority::SigningRequest.from_x509_csr(@pem_csr)
    csr.openssl_csr.should be_a(OpenSSL::X509::Request)
  end

  it "should expose the PEM encoded original CSR" do
    csr = CertificateAuthority::SigningRequest.from_x509_csr(@pem_csr)
    csr.raw_body.should == @pem_csr
    csr.raw_body.should be_a(String)
  end

  describe "transforming to a certificate" do
    before(:each) do
      @csr = CertificateAuthority::SigningRequest.from_x509_csr(@pem_csr)
      @cert = @csr.to_cert
    end

    it "should allow transformation to a certificate" do
      cert = @csr.to_cert
      cert.should_not be_nil
      cert.should be_a(CertificateAuthority::Certificate)
    end

    it "should be signable w/ a serial number" do
      root = CertificateAuthority::Certificate.new
      root.signing_entity = true
      root.subject.common_name = "chrischandler.name root"
      root.key_material.generate_key(1024)
      root.serial_number.number = 2
      root.sign!
      @cert.serial_number.number = 5
      @cert.parent = root
      result_cert = @cert.sign!
      result_cert.should be_a(OpenSSL::X509::Certificate)
      ## Verify the subjects and public key match
      @csr.distinguished_name.to_x509_name.should == result_cert.subject
      @csr.key_material.public_key.to_pem.should == result_cert.public_key.to_pem
    end
  end

  describe "Netscape SPKAC" do
    before(:each) do
      @spkac =<<EOF
MIICQDCCASgwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDVDEqzj21++aMWvN6zzwDXKKpR9g5hIeAPYqbUdaPFePhtz7R73l7fVxDeQZDQpQxTqts0/w0wEa/A1ehHCtAkDoTYzjwX8G0Gkb90poA156I8b4Cl1Q2veKbLsaOsMWItlXSU6HULQ5McfYfvEaPmIKiIr0UIFdzMDcy9TnY854w9TcQVvLJZcQkaM3dy/p9W4gg0a9hBJwwFUUR2UV/nEEi+++HbsOE46Z7Y3qoQhLrL4DNUrXUPDVeqac1SmNfKTA71QADbezWDfKi9habHHGXqk18i2Pl6uA2mpNPuSWnEHbQONgnfeoWZBvMWkwlolaBeWhGSmgcL/HqaRLlFAgMBAAEWADANBgkqhkiG9w0BAQQFAAOCAQEAp8wOvrl2QG9p1PS19dnrh4l0JWNAPB+d1kc64xUG6FAfGCKnOHzdDndTJfEERhWqFA0XL+mvKXCQsYKXkOuxYYmxJXZsdcCj7mOMhI2uMrEVd1ALFmG5WBW1Mo3nHHa/BX24fAOLv0+aGXYTz3oaMFydBw+XPZ26x9pO9LjlQQYGGyQRMpceWfej367KnR4a7IafDGBUI6OoWsx/7kQRIGkbmzi+dnU7HgpEExyz+uuxlUxrZqa13Ys8dBp62NBJWFanPl+AhMe8g/Li5aiERrMUbFtiXzOp48Si7J54fs+U3w0WoD9cdG5mN2Rn8Jog8azl+YC/XY987YGAi7Y8EQ==
EOF
    end

    it "should process a netscape SPKAC" do
      @csr = CertificateAuthority::SigningRequest.from_netscape_spkac(@spkac)
      @csr.should be_a(CertificateAuthority::SigningRequest)
    end
  end

  describe "Generating CSRs" do
    before(:each) do
      @key_pair =<<EOF
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
      @csr = CertificateAuthority::SigningRequest.new
      dn = CertificateAuthority::DistinguishedName.new
      dn.common_name = "localhost"
      @csr.distinguished_name = dn

      k = CertificateAuthority::KeyMaterial.from_x509_key_pair(@key_pair)
      @csr.key_material = k
    end

    it "should generate a CSR" do
      expected =<<EOF
-----BEGIN CERTIFICATE REQUEST-----
MIIBUjCBvAIAMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEF
AAOBjQAwgYkCgYEAsYhlX0a3/dAh5r12vl2FhOJuy2dbJXOnMSGMiIGbkOU/AHql
GpG8mGOMDFEdoGeKQz7P1hrPH1uuqtt6ph0q9W0Oh2i/M52w+1C/yIosolvCNdaK
264YpiMdQOtOqovP9IEHPh/OdYM1LrHecYCj9l/qD8WMd1Rt3aZLC5zStSMCAwEA
AaAAMA0GCSqGSIb3DQEBDQUAA4GBAICefvxP71/1uA5PG0tH2WbgDVF/pDPM+ff3
zdRuK6rpkUfDdtR4AwyEqNYptnPF8s/VDGI35JYzaTZZm/KXovupPWPccKHI/wKG
C4rJCPgEvyfe5Uce/sQHrnNbW4zJcPbw78lGrbop2k1tHbwY9QGha8Tj8ico7wu0
vvJ0eOXh
-----END CERTIFICATE REQUEST-----
EOF
      @csr.to_pem.should == expected
    end

    it "should generate a signed CSR" do
      @csr.digest = "SHA256"
      @csr.to_x509_csr.signature_algorithm.should == "sha256WithRSAEncryption"
    end
  end
end
