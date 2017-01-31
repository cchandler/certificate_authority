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
    expect(csr).not_to be_nil
    expect(csr).to be_a(CertificateAuthority::SigningRequest)
  end

  it "should generate a proper DN from the CSR" do
    csr = CertificateAuthority::SigningRequest.from_x509_csr(@pem_csr)
    expected_dn = CertificateAuthority::DistinguishedName.new
    expected_dn.country = "US"
    expected_dn.organization = "Certificate Authority"
    expected_dn.common_name = "www.chrischandler.name"
    expected_dn.locality = "San Francisco"
    expected_dn.state = "California"
    expect(csr.distinguished_name).to eq(expected_dn)
  end

  it "should expose the underlying OpenSSL CSR" do
    csr = CertificateAuthority::SigningRequest.from_x509_csr(@pem_csr)
    expect(csr.openssl_csr).to be_a(OpenSSL::X509::Request)
  end

  it "should expose the PEM encoded original CSR" do
    csr = CertificateAuthority::SigningRequest.from_x509_csr(@pem_csr)
    expect(csr.raw_body).to eq(@pem_csr)
    expect(csr.raw_body).to be_a(String)
  end

  describe "transforming to a certificate" do
    before(:each) do
      @csr = CertificateAuthority::SigningRequest.from_x509_csr(@pem_csr)
      @cert = @csr.to_cert
    end

    it "should allow transformation to a certificate" do
      cert = @csr.to_cert
      expect(cert).not_to be_nil
      expect(cert).to be_a(CertificateAuthority::Certificate)
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
      expect(result_cert).to be_a(OpenSSL::X509::Certificate)
      ## Verify the subjects and public key match
      expect(@csr.distinguished_name.to_x509_name).to eq(result_cert.subject)
      expect(@csr.key_material.public_key.to_pem).to eq(result_cert.public_key.to_pem)
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
      expect(@csr).to be_a(CertificateAuthority::SigningRequest)
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
MIIBUTCBuwIBADAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwgZ8wDQYJKoZIhvcNAQEB
BQADgY0AMIGJAoGBALGIZV9Gt/3QIea9dr5dhYTibstnWyVzpzEhjIiBm5DlPwB6
pRqRvJhjjAxRHaBnikM+z9Yazx9brqrbeqYdKvVtDodovzOdsPtQv8iKLKJbwjXW
ituuGKYjHUDrTqqLz/SBBz4fznWDNS6x3nGAo/Zf6g/FjHdUbd2mSwuc0rUjAgMB
AAEwDQYJKoZIhvcNAQENBQADgYEAZWLXHmJJyHz+9AdWUJ3U3pLHR/ghA1f3Ihyu
2PuYvwqfnGfGTA8DUnQx7l7J6ATIn76SBadmOquBBbbuhJG05WfKZt0oqCAPdsIa
XBlLOqVQmWR7YfwPc8CxclIYt1+HyCmBndXIDvGR0JO8/lEdSObZQYHV197hWOay
reDW940=
-----END CERTIFICATE REQUEST-----
EOF
      expect(@csr.to_pem).to eq(expected)
    end

    it "should generate a signed CSR" do
      @csr.digest = "SHA256"
      expect(@csr.to_x509_csr.signature_algorithm).to eq("sha256WithRSAEncryption")
    end

    it "should generate a CSR w/ a subjectAlternativeName extension" do
      alt_names = ["abc.com","somethingelse.com"]
      @csr.subject_alternative_names = alt_names

      expected_subjectAlt = CertificateAuthority::Extensions::SubjectAlternativeName.new
      expected_subjectAlt.dns_names =["abc.com", "somethingelse.com"]
      @csr.to_cert.extensions["subjectAltName"] == expected_subjectAlt
    end
  end
end
