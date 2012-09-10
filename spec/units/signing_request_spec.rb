require File.dirname(__FILE__) + '/units_helper'

describe CertificateAuthority::SigningRequest do
  before(:each) do
    @pem_csr =<<EOF
-----BEGIN CERTIFICATE REQUEST-----
MIIBnTCCAQYCAQAwXTELMAkGA1UEBhMCU0cxETAPBgNVBAoTCE0yQ3J5cHRvMRIw
EAYDVQQDEwlsb2NhbGhvc3QxJzAlBgkqhkiG9w0BCQEWGGFkbWluQHNlcnZlci5l
eGFtcGxlLmRvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAr1nYY1Qrll1r
uB/FqlCRrr5nvupdIN+3wF7q915tvEQoc74bnu6b8IbbGRMhzdzmvQ4SzFfVEAuM
MuTHeybPq5th7YDrTNizKKxOBnqE2KYuX9X22A1Kh49soJJFg6kPb9MUgiZBiMlv
tb7K3CHfgw5WagWnLl8Lb+ccvKZZl+8CAwEAAaAAMA0GCSqGSIb3DQEBBAUAA4GB
AHpoRp5YS55CZpy+wdigQEwjL/wSluvo+WjtpvP0YoBMJu4VMKeZi405R7o8oEwi
PdlrrliKNknFmHKIaCKTLRcU59ScA6ADEIWUzqmUzP5Cs6jrSRo3NKfg1bd09D1K
9rsQkRc9Urv9mRBIsredGnYECNeRaK5R1yzpOowninXC
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
    expected_dn.country = "SG"
    expected_dn.organization = "M2Crypto"
    expected_dn.common_name = "localhost"
    csr.distinguished_name.should == expected_dn
  end
end
