require File.dirname(__FILE__) + '/units_helper'

describe CertificateAuthority::Extensions do
  describe CertificateAuthority::Extensions::BasicConstraints do
    it "should only allow true/false" do
      basic_constraints = CertificateAuthority::Extensions::BasicConstraints.new
      expect(basic_constraints.valid?).to be_truthy
      basic_constraints.ca = "moo"
      expect(basic_constraints.valid?).to be_falsey
    end

    it "should respond to :path_len" do
      basic_constraints = CertificateAuthority::Extensions::BasicConstraints.new
      expect(basic_constraints.respond_to?(:path_len)).to be_truthy
    end

    it "should raise an error if :path_len isn't a non-negative integer" do
      basic_constraints = CertificateAuthority::Extensions::BasicConstraints.new
      expect {basic_constraints.path_len = "moo"}.to raise_error(ArgumentError)
      expect {basic_constraints.path_len = -1}.to raise_error(RuntimeError)
      expect {basic_constraints.path_len = 1.5}.to raise_error(RuntimeError)
    end

    it "should generate a proper OpenSSL extension string" do
      basic_constraints = CertificateAuthority::Extensions::BasicConstraints.new
      basic_constraints.ca = true
      basic_constraints.path_len = 2
      expect(basic_constraints.to_s).to eq("CA:true,pathlen:2")
    end

    it "should parse values from a proper OpenSSL extension string" do
      basic_constraints = CertificateAuthority::Extensions::BasicConstraints.parse("CA:true,pathlen:2", true)
      expect(basic_constraints.critical).to be_truthy
      expect(basic_constraints.ca).to be_truthy
      expect(basic_constraints.path_len).to eq(2)
    end
  end

  describe CertificateAuthority::Extensions::SubjectAlternativeName do
    it "should respond to :uris" do
      subjectAltName = CertificateAuthority::Extensions::SubjectAlternativeName.new
      expect(subjectAltName.respond_to?(:uris)).to be_truthy
    end

    it "should require 'uris' to be an Array" do
      subjectAltName = CertificateAuthority::Extensions::SubjectAlternativeName.new
      expect {subjectAltName.uris = "not an array"}.to raise_error(RuntimeError)
    end

    it "should generate a proper OpenSSL extension string for URIs" do
      subjectAltName = CertificateAuthority::Extensions::SubjectAlternativeName.new
      subjectAltName.uris = ["http://localhost.altname.example.com"]
      expect(subjectAltName.to_s).to eq("URI:http://localhost.altname.example.com")

      subjectAltName.uris = ["http://localhost.altname.example.com", "http://other.example.com"]
      expect(subjectAltName.to_s).to eq("URI:http://localhost.altname.example.com,URI:http://other.example.com")
    end

    it "should parse URIs from a proper OpenSSL extension string" do
      subjectAltName = CertificateAuthority::Extensions::SubjectAlternativeName.parse("URI:http://localhost.altname.example.com", false)
      expect(subjectAltName.uris).to eq(["http://localhost.altname.example.com"])

      subjectAltName = CertificateAuthority::Extensions::SubjectAlternativeName.parse("URI:http://localhost.altname.example.com,URI:http://other.example.com", false)
      expect(subjectAltName.uris).to eq(["http://localhost.altname.example.com", "http://other.example.com"])
    end

    it "should respond to :dns_names" do
      subjectAltName = CertificateAuthority::Extensions::SubjectAlternativeName.new
      expect(subjectAltName.respond_to?(:dns_names)).to be_truthy
    end

    it "should require 'dns_names' to be an Array" do
      subjectAltName = CertificateAuthority::Extensions::SubjectAlternativeName.new
      expect {subjectAltName.dns_names = "not an array"}.to raise_error(RuntimeError)
    end

    it "should generate a proper OpenSSL extension string for DNS names" do
      subjectAltName = CertificateAuthority::Extensions::SubjectAlternativeName.new
      subjectAltName.dns_names = ["localhost.altname.example.com"]
      expect(subjectAltName.to_s).to eq("DNS:localhost.altname.example.com")

      subjectAltName.dns_names = ["localhost.altname.example.com", "other.example.com"]
      expect(subjectAltName.to_s).to eq("DNS:localhost.altname.example.com,DNS:other.example.com")
    end

    it "should parse DNS names from a proper OpenSSL extension string" do
      subjectAltName = CertificateAuthority::Extensions::SubjectAlternativeName.parse("DNS:localhost.altname.example.com", false)
      expect(subjectAltName.dns_names).to eq(["localhost.altname.example.com"])

      subjectAltName = CertificateAuthority::Extensions::SubjectAlternativeName.parse("DNS:localhost.altname.example.com,DNS:other.example.com", false)
      expect(subjectAltName.dns_names).to eq(["localhost.altname.example.com", "other.example.com"])
    end

    it "should respond to :ips" do
      subjectAltName = CertificateAuthority::Extensions::SubjectAlternativeName.new
      expect(subjectAltName.respond_to?(:ips)).to be_truthy
    end

    it "should require 'ips' to be an Array" do
      subjectAltName = CertificateAuthority::Extensions::SubjectAlternativeName.new
      expect {subjectAltName.ips = "not an array"}.to raise_error(RuntimeError)
    end

    it "should generate a proper OpenSSL extension string for IPs" do
      subjectAltName = CertificateAuthority::Extensions::SubjectAlternativeName.new
      subjectAltName.ips = ["1.2.3.4"]
      expect(subjectAltName.to_s).to eq("IP:1.2.3.4")

      subjectAltName.ips = ["1.2.3.4", "5.6.7.8"]
      expect(subjectAltName.to_s).to eq("IP:1.2.3.4,IP:5.6.7.8")
    end

    it "should parse IPs from a proper OpenSSL extension string" do
      subjectAltName = CertificateAuthority::Extensions::SubjectAlternativeName.parse("IP:1.2.3.4", false)
      expect(subjectAltName.ips).to eq(["1.2.3.4"])

      subjectAltName = CertificateAuthority::Extensions::SubjectAlternativeName.parse("IP:1.2.3.4,IP:5.6.7.8", false)
      expect(subjectAltName.ips).to eq(["1.2.3.4", "5.6.7.8"])
    end

    describe 'emails' do
      let(:subject) { CertificateAuthority::Extensions::SubjectAlternativeName.new }

      it "should require 'emails' to be an Array" do
        expect {
          subject.emails = "not an array"
        }.to raise_error "Emails must be an array"
      end

      it "should generate a proper OpenSSL extension string for emails" do
        subject.emails = ["copy"]
        expect(subject.to_s).to eq("email:copy")

        subject.emails = ["copy", "foo@bar.com"]
        expect(subject.to_s).to eq("email:copy,email:foo@bar.com")
      end
    end

    it "should generate a proper OpenSSL extension string for URIs IPs and DNS names together" do
      subjectAltName = CertificateAuthority::Extensions::SubjectAlternativeName.new
      subjectAltName.ips = ["1.2.3.4"]
      expect(subjectAltName.to_s).to eq("IP:1.2.3.4")

      subjectAltName.dns_names = ["localhost.altname.example.com"]
      expect(subjectAltName.to_s).to eq("DNS:localhost.altname.example.com,IP:1.2.3.4")

      subjectAltName.dns_names = ["localhost.altname.example.com", "other.example.com"]
      expect(subjectAltName.to_s).to eq("DNS:localhost.altname.example.com,DNS:other.example.com,IP:1.2.3.4")

      subjectAltName.ips = ["1.2.3.4", "5.6.7.8"]
      expect(subjectAltName.to_s).to eq("DNS:localhost.altname.example.com,DNS:other.example.com,IP:1.2.3.4,IP:5.6.7.8")

      subjectAltName.uris = ["http://localhost.altname.example.com"]
      expect(subjectAltName.to_s).to eq("URI:http://localhost.altname.example.com,DNS:localhost.altname.example.com,DNS:other.example.com,IP:1.2.3.4,IP:5.6.7.8")

      subjectAltName.uris = ["http://localhost.altname.example.com", "http://other.altname.example.com"]
      expect(subjectAltName.to_s).to eq("URI:http://localhost.altname.example.com,URI:http://other.altname.example.com,DNS:localhost.altname.example.com,DNS:other.example.com,IP:1.2.3.4,IP:5.6.7.8")
    end

    it "should parse URIs IPs and DNS names together from a proper OpenSSL extension string" do
      subjectAltName = CertificateAuthority::Extensions::SubjectAlternativeName.parse("IP:1.2.3.4", false)
      expect(subjectAltName.ips).to eq(["1.2.3.4"])

      subjectAltName = CertificateAuthority::Extensions::SubjectAlternativeName.parse("DNS:localhost.altname.example.com,IP:1.2.3.4", false)
      expect(subjectAltName.dns_names).to eq(["localhost.altname.example.com"])

      subjectAltName = CertificateAuthority::Extensions::SubjectAlternativeName.parse("DNS:localhost.altname.example.com,DNS:other.example.com,IP:1.2.3.4", false)
      expect(subjectAltName.dns_names).to eq(["localhost.altname.example.com", "other.example.com"])

      subjectAltName = CertificateAuthority::Extensions::SubjectAlternativeName.parse("DNS:localhost.altname.example.com,DNS:other.example.com,IP:1.2.3.4,IP:5.6.7.8", false)
      expect(subjectAltName.ips).to eq(["1.2.3.4", "5.6.7.8"])

      subjectAltName = CertificateAuthority::Extensions::SubjectAlternativeName.parse("URI:http://localhost.altname.example.com,DNS:localhost.altname.example.com,DNS:other.example.com,IP:1.2.3.4,IP:5.6.7.8", false)
      expect(subjectAltName.uris).to eq(["http://localhost.altname.example.com"])

      subjectAltName = CertificateAuthority::Extensions::SubjectAlternativeName.parse("URI:http://localhost.altname.example.com,URI:http://other.altname.example.com,DNS:localhost.altname.example.com,DNS:other.example.com,IP:1.2.3.4,IP:5.6.7.8", false)
      expect(subjectAltName.uris).to eq(["http://localhost.altname.example.com", "http://other.altname.example.com"])

      subjectAltName.emails= ["copy", "foo@bar.com"]
      expect(subjectAltName.to_s).to eq("URI:http://localhost.altname.example.com,URI:http://other.altname.example.com,DNS:localhost.altname.example.com,DNS:other.example.com,IP:1.2.3.4,IP:5.6.7.8,email:copy,email:foo@bar.com")
    end
  end
end
