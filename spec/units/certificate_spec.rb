require File.dirname(__FILE__) + '/units_helper'

describe CertificateAuthority::Certificate do
  before(:each) do
    @certificate = CertificateAuthority::Certificate.new
  end

  describe CertificateAuthority::SigningEntity do
    it "should behave as a signing entity" do
      expect(@certificate.respond_to?(:is_signing_entity?)).to be_truthy
    end

    it "should only be a signing entity if it's identified as a CA", :rfc3280 => true do
      expect(@certificate.is_signing_entity?).to be_falsey
      @certificate.signing_entity = true
      expect(@certificate.is_signing_entity?).to be_truthy
    end

    describe "Root certificates" do
      before(:each) do
        @certificate.signing_entity = true
      end

      it "should be able to be identified as a root certificate" do
        expect(@certificate.is_root_entity?).to be_truthy
      end

      it "should only be a root certificate if the parent entity is itself", :rfc3280 => true do
        expect(@certificate.parent).to eq(@certificate)
      end

      it "should be a root certificate by default" do
        expect(@certificate.is_root_entity?).to be_truthy
      end

      it "should be able to self-sign" do
        @certificate.serial_number.number = 1
        @certificate.subject.common_name = "chrischandler.name"
        @certificate.key_material.generate_key(768)
        @certificate.sign!
        cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
        expect(cert.subject.to_s).to eq(cert.issuer.to_s)
      end

      it "should have the basicContraint CA:TRUE" do
        @certificate.serial_number.number = 1
        @certificate.subject.common_name = "chrischandler.name"
        @certificate.key_material.generate_key(768)
        @certificate.sign!
        cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
        expect(cert.extensions.map{|i| [i.oid,i.value] }.select{|i| i.first == "basicConstraints"}.first[1]).to eq("CA:TRUE")
      end
    end

    describe "Intermediate certificates" do
      before(:each) do
        @different_cert = CertificateAuthority::Certificate.new
        @different_cert.signing_entity = true
        @different_cert.subject.common_name = "chrischandler.name root"
        @different_cert.key_material.generate_key(768)
        @different_cert.serial_number.number = 2
        @different_cert.sign! #self-signed
        @certificate.parent = @different_cert
        @certificate.signing_entity = true
      end

      it "should be able to be identified as an intermediate certificate" do
        expect(@certificate.is_intermediate_entity?).to be_truthy
      end

      it "should not be identified as a root" do
        expect(@certificate.is_root_entity?).to be_falsey
      end

      it "should only be an intermediate certificate if the parent is a different entity" do
        expect(@certificate.parent).not_to eq(@certificate)
        expect(@certificate.parent).not_to be_nil
      end

      it "should correctly be signed by a parent certificate" do
        @certificate.subject.common_name = "chrischandler.name"
        @certificate.key_material.generate_key(768)
        @certificate.signing_entity = true
        @certificate.serial_number.number = 1
        @certificate.sign!
        cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
        expect(cert.subject.to_s).not_to eq(cert.issuer.to_s)
      end

      it "should have the basicContraint CA:TRUE" do
        @certificate.subject.common_name = "chrischandler.name"
        @certificate.key_material.generate_key(768)
        @certificate.signing_entity = true
        @certificate.serial_number.number = 3
        @certificate.sign!
        cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
        expect(cert.extensions.map{|i| [i.oid,i.value] }.select{|i| i.first == "basicConstraints"}.first[1]).to eq("CA:TRUE")
      end

    end

    describe "Terminal certificates" do
      before(:each) do
        @different_cert = CertificateAuthority::Certificate.new
        @different_cert.signing_entity = true
        @different_cert.subject.common_name = "chrischandler.name root"
        @different_cert.key_material.generate_key(768)
        @different_cert.serial_number.number = 1
        @different_cert.sign! #self-signed
        @certificate.parent = @different_cert
      end

      it "should not be identified as an intermediate certificate" do
        expect(@certificate.is_intermediate_entity?).to be_falsey
      end

      it "should not be identified as a root" do
        expect(@certificate.is_root_entity?).to be_falsey
      end

      it "should have the basicContraint CA:FALSE" do
        @certificate.subject.common_name = "chrischandler.name"
        @certificate.key_material.generate_key(768)
        @certificate.signing_entity = false
        @certificate.serial_number.number = 1
        @certificate.sign!
        cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
        expect(cert.extensions.map{|i| [i.oid,i.value] }.select{|i| i.first == "basicConstraints"}.first[1]).to eq("CA:FALSE")
      end
    end


    it "should be able to be identified as a root certificate" do
      expect(@certificate.respond_to?(:is_root_entity?)).to be_truthy
    end
  end #End of SigningEntity

  describe "Signed certificates" do
    before(:each) do
      @certificate = CertificateAuthority::Certificate.new
      @certificate.subject.common_name = "chrischandler.name"
      @certificate.key_material.generate_key(768)
      @certificate.serial_number.number = 1
      @certificate.sign!
    end

    it "should have a PEM encoded certificate body available" do
      expect(@certificate.to_pem).not_to be_nil
      expect(OpenSSL::X509::Certificate.new(@certificate.to_pem)).not_to be_nil
    end
  end

  describe "X.509 V3 Extensions on Signed Certificates" do
    before(:each) do
      @certificate = CertificateAuthority::Certificate.new
      @certificate.subject.common_name = "chrischandler.name"
      @certificate.key_material.generate_key(768)
      @certificate.serial_number.number = 1
      @signing_profile = {
        "extensions" => {
          "subjectAltName" => {"uris" => ["www.chrischandler.name"]},
          "certificatePolicies" => {
            "policy_identifier" => "1.3.5.7",
            "cps_uris" => ["http://my.host.name/", "http://my.your.name/"],
            "user_notice" => {
             "explicit_text" => "Testing!", "organization" => "RSpec Test organization name", "notice_numbers" => "1,2,3,4"
            }
          }
        }
      }
      @certificate.sign!(@signing_profile)
    end

    describe "SubjectAltName" do
      before(:each) do
        @certificate = CertificateAuthority::Certificate.new
        @certificate.subject.common_name = "chrischandler.name"
        @certificate.key_material.generate_key(768)
        @certificate.serial_number.number = 1
      end

      it "should have a subjectAltName if specified" do
        @certificate.sign!({"extensions" => {"subjectAltName" => {"uris" => ["www.chrischandler.name"]}}})
        cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
        expect(cert.extensions.map(&:oid).include?("subjectAltName")).to be_truthy
      end

      it "should NOT have a subjectAltName if one was not specified" do
        @certificate.sign!
        cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
        expect(cert.extensions.map(&:oid).include?("subjectAltName")).to be_falsey
      end

      it 'should replace email:copy with email address' do
        @certificate.subject.email_address = 'foo@bar.com'
        @certificate.sign!(
            { "extensions" => { "subjectAltName" => { 'emails' => %w[copy fubar@bar.com] } } }
        )
        cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
        alt = cert.extensions.select { |e| e.oid == 'subjectAltName' }.first
        expect(alt.value).to eq('email:foo@bar.com, email:fubar@bar.com')
      end
    end

    describe "AuthorityInfoAccess" do
      before(:each) do
        @certificate = CertificateAuthority::Certificate.new
        @certificate.subject.common_name = "chrischandler.name"
        @certificate.key_material.generate_key(768)
        @certificate.serial_number.number = 1
      end

      it "should have an authority info access if specified" do
        @certificate.sign!({"extensions" => {"authorityInfoAccess" => {"ocsp" => ["www.chrischandler.name"]}}})
        cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
        expect(cert.extensions.map(&:oid).include?("authorityInfoAccess")).to be_truthy
      end
    end

    describe "CrlDistributionPoints" do
      before(:each) do
        @certificate = CertificateAuthority::Certificate.new
        @certificate.subject.common_name = "chrischandler.name"
        @certificate.key_material.generate_key(768)
        @certificate.serial_number.number = 1
      end

      it "should have a crlDistributionPoint if specified" do
        @certificate.sign!({"extensions" => {"crlDistributionPoints" => {"uris" => ["http://crlThingy.com"]}}})
        cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
        expect(cert.extensions.map(&:oid).include?("crlDistributionPoints")).to be_truthy
      end

      it "should NOT have a crlDistributionPoint if one was not specified" do
        @certificate.sign!
        cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
        expect(cert.extensions.map(&:oid).include?("crlDistributionPoints")).to be_falsey
      end
    end


    describe "CertificatePolicies" do
      before(:each) do
        @certificate = CertificateAuthority::Certificate.new
        @certificate.subject.common_name = "chrischandler.name"
        @certificate.key_material.generate_key(768)
        @certificate.serial_number.number = 1
      end

      it "should have a certificatePolicy if specified" do
        @certificate.sign!({
          "extensions" => {
            "certificatePolicies" => {
              "policy_identifier" => "1.3.5.7",
              "cps_uris" => ["http://my.host.name/", "http://my.your.name/"]
            }
          }
        })
        cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
        expect(cert.extensions.map(&:oid).include?("certificatePolicies")).to be_truthy
      end

      pending "should contain a nested userNotice if specified" do
        #pending
         @certificate.sign!({
           "extensions" => {
             "certificatePolicies" => {
               "policy_identifier" => "1.3.5.7",
               "cps_uris" => ["http://my.host.name/", "http://my.your.name/"],
               "user_notice" => {
                "explicit_text" => "Testing explicit text!", "organization" => "RSpec Test organization name", "notice_numbers" => "1,2,3,4"
               }
             }
           }
         })
         cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
         expect(cert.extensions.map(&:oid).include?("certificatePolicies")).to be_truthy
         ## Checking OIDs after they've run through OpenSSL is a pain...
         ## The nicely structured data will be flattened to a single String
         cert.extensions.each do |ext|
           if ext.oid == "certificatePolicies"
             expect(ext.to_a[1]).to include("Testing explicit text!")
           end
         end
      end

      it "should NOT include a certificatePolicy if not specified" do
        @certificate.sign!
        cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
        expect(cert.extensions.map(&:oid).include?("certificatePolicies")).to be_falsey
      end
    end


    it "should support BasicConstraints" do
      cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
      expect(cert.extensions.map(&:oid).include?("basicConstraints")).to be_truthy
    end

    it "should support subjectKeyIdentifier" do
      cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
      expect(cert.extensions.map(&:oid).include?("subjectKeyIdentifier")).to be_truthy
    end

    it "should support authorityKeyIdentifier" do
      cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
      expect(cert.extensions.map(&:oid).include?("authorityKeyIdentifier")).to be_truthy
    end

    it "should order subjectKeyIdentifier before authorityKeyIdentifier" do
      cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
      expect(cert.extensions.map(&:oid).select do |oid|
        ["subjectKeyIdentifier", "authorityKeyIdentifier"].include?(oid)
      end).to eq(["subjectKeyIdentifier", "authorityKeyIdentifier"])
    end

    it "should support keyUsage" do
      cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
      expect(cert.extensions.map(&:oid).include?("keyUsage")).to be_truthy
    end

    it "should support extendedKeyUsage" do
      cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
      expect(cert.extensions.map(&:oid).include?("extendedKeyUsage")).to be_truthy
    end
  end

  describe "Signing profile" do
    before(:each) do
      @certificate = CertificateAuthority::Certificate.new
      @certificate.subject.common_name = "chrischandler.name"
      @certificate.key_material.generate_key(768)
      @certificate.serial_number.number = 1

      @signing_profile = {
        "extensions" => {
          "basicConstraints" => {"ca" => false},
          "crlDistributionPoints" => {"uri" => "http://notme.com/other.crl" },
          "subjectKeyIdentifier" => {},
          "authorityKeyIdentifier" => {},
          "authorityInfoAccess" => {"ocsp" => ["http://youFillThisOut/ocsp/"], "ca_issuers" => ["http://me.com/other.crt"] },
          "keyUsage" => {"usage" => ["digitalSignature","nonRepudiation"] },
          "extendedKeyUsage" => {"usage" => [ "serverAuth","clientAuth"]},
          "subjectAltName" => {"uris" => ["http://subdomains.youFillThisOut/"]},
          "certificatePolicies" => {
          "policy_identifier" => "1.3.5.8", "cps_uris" => ["http://my.host.name/", "http://my.your.name/"], "user_notice" => {
             "explicit_text" => "Explicit Text Here", "organization" => "Organization name", "notice_numbers" => "1,2,3,4"
          }
        }
      }
    }
    end

    it "should be able to sign with an optional policy hash" do
      @certificate.sign!(@signing_profile)
    end

    it "should support a default signing digest of SHA512" do
      @certificate.sign!(@signing_profile)
      cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
      expect(cert.signature_algorithm).to eq("sha512WithRSAEncryption")
    end

    it "should support a configurable digest algorithm" do
      @signing_profile.merge!({"digest" => "SHA1"})
      @certificate.sign!(@signing_profile)
      cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
      expect(cert.signature_algorithm).to eq("sha1WithRSAEncryption")
    end

  end

  describe "from_openssl" do
    before(:each) do
      @pem_cert=<<CERT
-----BEGIN CERTIFICATE-----
MIICFDCCAc6gAwIBAgIJAPDLgMilKuayMA0GCSqGSIb3DQEBBQUAMEgxCzAJBgNV
BAYTAlVTMRMwEQYDVQQIEwpTb21lLVN0YXRlMQowCAYDVQQKEwEgMRgwFgYDVQQD
Ew9WZXJ5IFNtYWxsIENlcnQwHhcNMTIwNTAzMDMyODI1WhcNMTMwNTAzMDMyODI1
WjBIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKU29tZS1TdGF0ZTEKMAgGA1UEChMB
IDEYMBYGA1UEAxMPVmVyeSBTbWFsbCBDZXJ0MEwwDQYJKoZIhvcNAQEBBQADOwAw
OAIxAN6+33+WQ3FBMt+vMhshxOj+8W7V64pDKCJ3pVlnSn36imBWqrN0AGWX8qjv
S+GzGwIDAQABo4GqMIGnMB0GA1UdDgQWBBRMUQ/HpPrAkKOufS5h+xPtEuzyWDB4
BgNVHSMEcTBvgBRMUQ/HpPrAkKOufS5h+xPtEuzyWKFMpEowSDELMAkGA1UEBhMC
VVMxEzARBgNVBAgTClNvbWUtU3RhdGUxCjAIBgNVBAoTASAxGDAWBgNVBAMTD1Zl
cnkgU21hbGwgQ2VydIIJAPDLgMilKuayMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcN
AQEFBQADMQAq0CsqEChn4uf6MkXYBwaAAmS3JLmagyliJe5zM3y8dZz6Em2Ugb8o
1cCaKaHJHSg=
-----END CERTIFICATE-----
CERT
      @openssl_cert = OpenSSL::X509::Certificate.new @pem_cert
      @small_cert = CertificateAuthority::Certificate.from_openssl @openssl_cert
    end

    it "should reject non-Certificate arguments" do
      expect { CertificateAuthority::Certificate.from_openssl "a string" }.to raise_error(RuntimeError)
    end

    it "should only be missing a private key" do
      expect(@small_cert).not_to be_valid
      @small_cert.key_material.private_key = "data"
      expect(@small_cert).to be_valid
    end

    it "should check to make sure that if a certificate had extensions they were imported" do
      cert_path = File.join(File.dirname(__FILE__),"..","samples","certs","github.com.pem")
      openssl_cert = OpenSSL::X509::Certificate.new(File.read(cert_path))
      @cert_with_extensions = CertificateAuthority::Certificate.from_openssl(openssl_cert)

      expected_basicConstraints = CertificateAuthority::Extensions::BasicConstraints.new
      expected_basicConstraints.critical = true
      expected_basicConstraints.ca = false
      expect(@cert_with_extensions.extensions["basicConstraints"]).to eq(expected_basicConstraints)

      expected_crlDistributionPoints = CertificateAuthority::Extensions::CrlDistributionPoints.new
      expected_crlDistributionPoints.uris = ["http://crl3.digicert.com/ev2009a.crl","http://crl4.digicert.com/ev2009a.crl"]
      expect(@cert_with_extensions.extensions["crlDistributionPoints"]).to eq(expected_crlDistributionPoints)

      expected_subjectAlt = CertificateAuthority::Extensions::SubjectAlternativeName.new
      expected_subjectAlt.dns_names =["github.com", "www.github.com"]
      expect(@cert_with_extensions.extensions["subjectAltName"]).to eq(expected_subjectAlt)

      expected_subjectKeyIdentifier = CertificateAuthority::Extensions::SubjectKeyIdentifier.new
      expected_subjectKeyIdentifier.identifier = "87:D1:8F:19:6E:E4:87:6F:53:8C:77:91:07:50:DF:A3:BF:55:47:20"
      expect(@cert_with_extensions.extensions["subjectKeyIdentifier"]).to eq(expected_subjectKeyIdentifier)

      expected_authorityKeyIdentifier = CertificateAuthority::Extensions::AuthorityKeyIdentifier.new
      expected_authorityKeyIdentifier.identifier = "keyid:4C:58:CB:25:F0:41:4F:52:F4:28:C8:81:43:9B:A6:A8:A0:E6:92:E5"
      expect(@cert_with_extensions.extensions["authorityKeyIdentifier"]).to eq(expected_authorityKeyIdentifier)

      expected_authorityInfoAccess = CertificateAuthority::Extensions::AuthorityInfoAccess.new
      expected_authorityInfoAccess.ocsp << "URI:http://ocsp.digicert.com"
      expected_authorityInfoAccess.ca_issuers << "URI:http://www.digicert.com/CACerts/DigiCertHighAssuranceEVCA-1.crt"
      expect(@cert_with_extensions.extensions["authorityInfoAccess"]).to eq(expected_authorityInfoAccess)

      expected_keyUsage = CertificateAuthority::Extensions::KeyUsage.new
      expected_keyUsage.critical = true
      # This one is goofy. Though you have to tell openssl 'digitalSignature'
      # it will parse and return 'Digital Signature' even though those should
      # be identical.
      expected_keyUsage.usage = ["Digital Signature", "Key Encipherment"]
      expect(@cert_with_extensions.extensions["keyUsage"]).to eq(expected_keyUsage)

      expected_extendedKeyUsage = CertificateAuthority::Extensions::ExtendedKeyUsage.new
      # Same asymmetric specify vs parse as above
      expected_extendedKeyUsage.usage = ["TLS Web Server Authentication", "TLS Web Client Authentication"]
      expect(@cert_with_extensions.extensions["extendedKeyUsage"]).to eq(expected_extendedKeyUsage)
    end
  end

  it "should have a distinguished name" do
    expect(@certificate.distinguished_name).not_to be_nil
  end

  it "should have a serial number" do
    expect(@certificate.serial_number).not_to be_nil
  end

  it "should have a subject" do
    expect(@certificate.subject).not_to be_nil
  end

  it "should be able to have a parent entity" do
    expect(@certificate.respond_to?(:parent)).to be_truthy
  end

  it "should have key material" do
    expect(@certificate.key_material).not_to be_nil
  end

  it "should have a not_before field" do
    expect(@certificate.not_before).not_to be_nil
  end

  it "should have a not_after field" do
    expect(@certificate.not_after).not_to be_nil
  end

  it "should default to one year validity" do
    day  = 60 * 60 * 24
    year = day * 365
    expect(@certificate.not_after).to be < Time.now + year + day and
    expect(@certificate.not_after).to be > Time.now + year - day
  end

  it "should be able to have a revoked at time" do
    expect(@certificate.revoked?).to be_falsey
    @certificate.revoked_at = Time.now.utc
    expect(@certificate.revoked?).to be_truthy
  end

end
