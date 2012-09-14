require File.dirname(__FILE__) + '/units_helper'

describe "Using OpenSSL" do

  shared_examples_for "an ossl issuer and its signed cert" do
    it "should issue a certificate verified by the issuer" do
      @signed.verify(@issuer.public_key ).should be_true
    end

    it "should issue a certificate with a matching issuer subject string" do
      @signed.issuer.to_s.should == @issuer.subject.to_s
    end

    it "should issue a certificate with a matching issuer subject openssl name" do
      @signed.issuer.should == @issuer.subject
    end

  end

  context "Singing CSRs" do
    shared_examples_for "a csr operation" do
      before :all do
        @ca = sample_file("certs/ca.crt").read
        @ca_key = sample_file("certs/ca.key").read

        @issuer = OpenSSL::X509::Certificate.new(@ca)
        issuer_ca = CertificateAuthority::Certificate.from_openssl(@issuer)
        issuer_ca.key_material.private_key = OpenSSL::PKey::RSA.new(@ca_key)

        @our_csr = CertificateAuthority::SigningRequest.from_x509_csr(@csr_pem)
        signed = @our_csr.to_cert
        signed.parent = issuer_ca
        signed.serial_number.number = 2

        signed.sign!

        @cert = @signed = OpenSSL::X509::Certificate.new(signed.to_pem)
      end
      it_should_behave_like "an ossl issuer and its signed cert"
    end

    context "With a server CSR" do
      before :all do
        @csr_pem = sample_file("certs/server.csr").read
      end

      it_should_behave_like "a csr operation"
    end

    context "With a client CSR" do
      before :all do
        @csr_pem = sample_file("certs/client.csr").read
      end

      it_should_behave_like "a csr operation"
    end
  end

  context "Handling externally supplied CAs and certs" do
    shared_examples_for "comparing a pair of openssl certs" do
      context "using openssl" do
        before :all do
          @issuer = @ca
          @signed = @cert
        end
        it_should_behave_like "an ossl issuer and its signed cert"
      end

      context "using certificate_authority" do
        before :all do
          # from openssl
          @our_ca = CertificateAuthority::Certificate.from_openssl(@ca)
          @our_cert = CertificateAuthority::Certificate.from_openssl(@cert)

          # and back
          @issuer = OpenSSL::X509::Certificate.new(@our_ca.to_pem)
          @signed = OpenSSL::X509::Certificate.new(@our_cert.to_pem)
        end

        it "should match the original openssl ca material" do
          back = OpenSSL::X509::Certificate.new(@our_ca.to_pem)
          back.subject.should == @ca.subject
        end

        it "should match the original openssl cert material" do
          back = OpenSSL::X509::Certificate.new(@our_cert.to_pem)
          back.subject.should == @cert.subject
        end

        it_should_behave_like "an ossl issuer and its signed cert"
      end
    end

    context "A custom CA signing a client cert" do
      before :all do
        @ca = OpenSSL::X509::Certificate.new(sample_file("certs/ca.crt").read)
        @cert = OpenSSL::X509::Certificate.new(sample_file("certs/client.crt").read)
      end

      it_should_behave_like "comparing a pair of openssl certs"
    end

    context "A custom CA signing a server cert" do
      before :all do
        @ca = OpenSSL::X509::Certificate.new(sample_file("certs/ca.crt").read)
        @cert = OpenSSL::X509::Certificate.new(sample_file("certs/server.crt").read)
      end

      it_should_behave_like "comparing a pair of openssl certs"
    end

    context "Github's signer" do
      before :all do
        @ca = OpenSSL::X509::Certificate.new(sample_file("certs/DigiCertHighAssuranceEVCA-1.pem").read)
        @cert = OpenSSL::X509::Certificate.new(sample_file("certs/github.com.pem").read)
      end
      it_should_behave_like "comparing a pair of openssl certs"
    end

    context "Apple's WWDR signer" do
      before :all do
        @ca = OpenSSL::X509::Certificate.new(sample_file("certs/apple_wwdr_issuer.pem").read)
        @cert = OpenSSL::X509::Certificate.new(sample_file("certs/apple_wwdr_issued_cert.pem").read)
      end
      it_should_behave_like "comparing a pair of openssl certs"
    end
  end
end
