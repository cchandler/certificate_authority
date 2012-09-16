require File.dirname(__FILE__) + '/units_helper'

describe CertificateAuthority::Certificate do
  before(:each) do
    @certificate = CertificateAuthority::Certificate.new
  end

  describe CertificateAuthority::SigningEntity do
    it "should behave as a signing entity" do
      @certificate.respond_to?(:is_signing_entity?).should be_true
    end

    it "should only be a signing entity if it's identified as a CA", :rfc3280 => true do
      @certificate.is_signing_entity?.should be_false
      @certificate.signing_entity = true
      @certificate.is_signing_entity?.should be_true
    end

    describe "Root certificates" do
      before(:each) do
        @certificate.signing_entity = true
      end

      it "should be able to be identified as a root certificate" do
        @certificate.is_root_entity?.should be_true
      end

      it "should only be a root certificate if the parent entity is itself", :rfc3280 => true do
        @certificate.parent.should == @certificate
      end

      it "should be a root certificate by default" do
        @certificate.is_root_entity?.should be_true
      end

      it "should be able to self-sign" do
        @certificate.serial_number.number = 1
        @certificate.subject.common_name = "chrischandler.name"
        @certificate.key_material.generate_key(1024)
        @certificate.sign!
        cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
        cert.subject.to_s.should == cert.issuer.to_s
      end

      it "should have the basicContraint CA:TRUE" do
        @certificate.serial_number.number = 1
        @certificate.subject.common_name = "chrischandler.name"
        @certificate.key_material.generate_key(1024)
        @certificate.sign!
        cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
        cert.extensions.map{|i| [i.oid,i.value] }.select{|i| i.first == "basicConstraints"}.first[1].should == "CA:TRUE"
      end
    end

    describe "Intermediate certificates" do
      before(:each) do
        @different_cert = CertificateAuthority::Certificate.new
        @different_cert.signing_entity = true
        @different_cert.subject.common_name = "chrischandler.name root"
        @different_cert.key_material.generate_key(1024)
        @different_cert.serial_number.number = 2
        @different_cert.sign! #self-signed
        @certificate.parent = @different_cert
        @certificate.signing_entity = true
      end

      it "should be able to be identified as an intermediate certificate" do
        @certificate.is_intermediate_entity?.should be_true
      end

      it "should not be identified as a root" do
        @certificate.is_root_entity?.should be_false
      end

      it "should only be an intermediate certificate if the parent is a different entity" do
        @certificate.parent.should_not == @certificate
        @certificate.parent.should_not be_nil
      end

      it "should correctly be signed by a parent certificate" do
        @certificate.subject.common_name = "chrischandler.name"
        @certificate.key_material.generate_key(1024)
        @certificate.signing_entity = true
        @certificate.serial_number.number = 1
        @certificate.sign!
        cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
        cert.subject.to_s.should_not == cert.issuer.to_s
      end

      it "should have the basicContraint CA:TRUE" do
        @certificate.subject.common_name = "chrischandler.name"
        @certificate.key_material.generate_key(1024)
        @certificate.signing_entity = true
        @certificate.serial_number.number = 3
        @certificate.sign!
        cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
        cert.extensions.map{|i| [i.oid,i.value] }.select{|i| i.first == "basicConstraints"}.first[1].should == "CA:TRUE"
      end

    end

    describe "Terminal certificates" do
      before(:each) do
        @different_cert = CertificateAuthority::Certificate.new
        @different_cert.signing_entity = true
        @different_cert.subject.common_name = "chrischandler.name root"
        @different_cert.key_material.generate_key(1024)
        @different_cert.serial_number.number = 1
        @different_cert.sign! #self-signed
        @certificate.parent = @different_cert
      end

      it "should not be identified as an intermediate certificate" do
        @certificate.is_intermediate_entity?.should be_false
      end

      it "should not be identified as a root" do
        @certificate.is_root_entity?.should be_false
      end

      it "should have the basicContraint CA:FALSE" do
        @certificate.subject.common_name = "chrischandler.name"
        @certificate.key_material.generate_key(1024)
        @certificate.signing_entity = false
        @certificate.serial_number.number = 1
        @certificate.sign!
        cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
        cert.extensions.map{|i| [i.oid,i.value] }.select{|i| i.first == "basicConstraints"}.first[1].should == "CA:FALSE"
      end
    end


    it "should be able to be identified as a root certificate" do
      @certificate.respond_to?(:is_root_entity?).should be_true
    end
  end #End of SigningEntity

  describe "Signed certificates" do
    before(:each) do
      @certificate = CertificateAuthority::Certificate.new
      @certificate.subject.common_name = "chrischandler.name"
      @certificate.key_material.generate_key(1024)
      @certificate.serial_number.number = 1
      @certificate.sign!
    end

    it "should have a PEM encoded certificate body available" do
      @certificate.to_pem.should_not be_nil
      OpenSSL::X509::Certificate.new(@certificate.to_pem).should_not be_nil
    end
  end

  describe "X.509 V3 Extensions on Signed Certificates" do
    before(:each) do
      @certificate = CertificateAuthority::Certificate.new
      @certificate.subject.common_name = "chrischandler.name"
      @certificate.key_material.generate_key(1024)
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
        @certificate.key_material.generate_key(1024)
        @certificate.serial_number.number = 1
      end

      it "should have a subjectAltName if specified" do
        @certificate.sign!({"extensions" => {"subjectAltName" => {"uris" => ["www.chrischandler.name"]}}})
        cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
        cert.extensions.map(&:oid).include?("subjectAltName").should be_true
      end

      it "should NOT have a subjectAltName if one was not specified" do
        @certificate.sign!
        cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
        cert.extensions.map(&:oid).include?("subjectAltName").should be_false
      end
    end

    describe "AuthorityInfoAccess" do
      before(:each) do
        @certificate = CertificateAuthority::Certificate.new
        @certificate.subject.common_name = "chrischandler.name"
        @certificate.key_material.generate_key(1024)
        @certificate.serial_number.number = 1
      end

      it "should have an authority info access if specified" do
        @certificate.sign!({"extensions" => {"authorityInfoAccess" => {"ocsp" => ["www.chrischandler.name"]}}})
        cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
        cert.extensions.map(&:oid).include?("authorityInfoAccess").should be_true
      end
    end

    describe "CrlDistributionPoints" do
      before(:each) do
        @certificate = CertificateAuthority::Certificate.new
        @certificate.subject.common_name = "chrischandler.name"
        @certificate.key_material.generate_key(1024)
        @certificate.serial_number.number = 1
      end

      it "should have a crlDistributionPoint if specified" do
        @certificate.sign!({"extensions" => {"crlDistributionPoints" => {"uri" => ["http://crlThingy.com"]}}})
        cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
        cert.extensions.map(&:oid).include?("crlDistributionPoints").should be_true
      end

      it "should NOT have a crlDistributionPoint if one was not specified" do
        @certificate.sign!
        cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
        cert.extensions.map(&:oid).include?("crlDistributionPoints").should be_false
      end
    end


    describe "CertificatePolicies" do
      before(:each) do
        @certificate = CertificateAuthority::Certificate.new
        @certificate.subject.common_name = "chrischandler.name"
        @certificate.key_material.generate_key(1024)
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
        cert.extensions.map(&:oid).include?("certificatePolicies").should be_true
      end

      it "should contain a nested userNotice if specified" do
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
         cert.extensions.map(&:oid).include?("certificatePolicies").should be_true
         ## Checking OIDs after they've run through OpenSSL is a pain...
         ## The nicely structured data will be flattened to a single String
         cert.extensions.each do |ext|
           if ext.oid == "certificatePolicies"
             ext.to_a[1].should include("Testing explicit text!")
           end
         end
      end

      it "should NOT include a certificatePolicy if not specified" do
        @certificate.sign!
        cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
        cert.extensions.map(&:oid).include?("certificatePolicies").should be_false
      end
    end


    it "should support BasicContraints" do
      cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
      cert.extensions.map(&:oid).include?("basicConstraints").should be_true
    end

    it "should support subjectKeyIdentifier" do
      cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
      cert.extensions.map(&:oid).include?("subjectKeyIdentifier").should be_true
    end

    it "should support authorityKeyIdentifier" do
      cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
      cert.extensions.map(&:oid).include?("authorityKeyIdentifier").should be_true
    end

    it "should order subjectKeyIdentifier before authorityKeyIdentifier" do
      cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
      cert.extensions.map(&:oid).select do |oid|
        ["subjectKeyIdentifier", "authorityKeyIdentifier"].include?(oid)
      end.should == ["subjectKeyIdentifier", "authorityKeyIdentifier"]
    end

    it "should support keyUsage" do
      cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
      cert.extensions.map(&:oid).include?("keyUsage").should be_true
    end

    it "should support extendedKeyUsage" do
      cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
      cert.extensions.map(&:oid).include?("extendedKeyUsage").should be_true
    end
  end

  describe "Signing profile" do
    before(:each) do
      @certificate = CertificateAuthority::Certificate.new
      @certificate.subject.common_name = "chrischandler.name"
      @certificate.key_material.generate_key(1024)
      @certificate.serial_number.number = 1

      @signing_profile = {
        "extensions" => {
          "basicConstraints" => {"ca" => false},
          "crlDistributionPoints" => {"uri" => "http://notme.com/other.crl" },
          "subjectKeyIdentifier" => {},
          "authorityKeyIdentifier" => {},
          "authorityInfoAccess" => {"ocsp" => ["http://youFillThisOut/ocsp/"] },
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
      cert.signature_algorithm.should == "sha512WithRSAEncryption"
    end

    it "should support a configurable digest algorithm" do
      @signing_profile.merge!({"digest" => "SHA1"})
      @certificate.sign!(@signing_profile)
      cert = OpenSSL::X509::Certificate.new(@certificate.to_pem)
      cert.signature_algorithm.should == "sha1WithRSAEncryption"
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
      lambda { CertificateAuthority::Certificate.from_openssl "a string" }.should raise_error
    end

    it "should only be missing a private key" do
      @small_cert.should_not be_valid
      @small_cert.key_material.private_key = "data"
      @small_cert.should be_valid
    end
  end

  it "should have a distinguished name" do
    @certificate.distinguished_name.should_not be_nil
  end

  it "should have a serial number" do
    @certificate.serial_number.should_not be_nil
  end

  it "should have a subject" do
    @certificate.subject.should_not be_nil
  end

  it "should be able to have a parent entity" do
    @certificate.respond_to?(:parent).should be_true
  end

  it "should have key material" do
    @certificate.key_material.should_not be_nil
  end

  it "should have a not_before field" do
    @certificate.not_before.should_not be_nil
  end

  it "should have a not_after field" do
    @certificate.not_after.should_not be_nil
  end

  it "should default to one year validity" do
    @certificate.not_after.should < Time.now + 65 * 60 * 24 * 365 and
    @certificate.not_after.should > Time.now + 55 * 60 * 24 * 365
  end

  it "should be able to have a revoked at time" do
    @certificate.revoked?.should be_false
    @certificate.revoked_at = Time.now
    @certificate.revoked?.should be_true
  end

end
