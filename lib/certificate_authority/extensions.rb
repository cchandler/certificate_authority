module CertificateAuthority
  module Extensions
    module ExtensionAPI
      def to_s
        raise "Implementation required"
      end

      def config_extensions
        {}
      end

      def openssl_identifier
        raise "Implementation required"
      end
    end

    # Specifies whether an X.509v3 certificate can act as a CA, signing other
    # certificates to be verified. If set, a path length constraint can also be
    # specified.
    # Reference: Section 4.2.1.10 of RFC3280
    # http://tools.ietf.org/html/rfc3280#section-4.2.1.10
    class BasicConstraints
      include ExtensionAPI
      include ActiveModel::Validations
      attr_accessor :ca
      attr_accessor :path_len
      validates :ca, :inclusion => [true,false]

      def initialize
        self.ca = false
      end

      def is_ca?
        self.ca
      end

      def path_len=(value)
        raise "path_len must be a non-negative integer" if value < 0 or !value.is_a?(Fixnum)
        @path_len = value
      end

      def openssl_identifier
        "basicConstraints"
      end

      def to_s
        result = ""
        result += "CA:#{self.ca}"
        result += ",pathlen:#{self.path_len}" unless self.path_len.nil?
        result
      end
    end

    # Specifies where CRL information be be retrieved. This extension isn't
    # critical, but is recommended for proper CAs.
    # Reference: Section 4.2.1.14 of RFC3280
    # http://tools.ietf.org/html/rfc3280#section-4.2.1.14
    class CrlDistributionPoints
      include ExtensionAPI

      attr_accessor :uri

      def initialize
        # self.uri = "http://moo.crlendPoint.example.com/something.crl"
      end

      def openssl_identifier
        "crlDistributionPoints"
      end

      ## NB: At this time it seems OpenSSL's extension handlers don't support
      ## any of the config options the docs claim to support... everything comes back
      ## "missing value" on GENERAL NAME. Even if copied verbatim
      def config_extensions
        {
          # "custom_crl_fields" => {"fullname" => "URI:#{fullname}"},
          # "issuer_sect" => {"CN" => "crlissuer.com", "C" => "US", "O" => "shudder"}
        }
      end

      def to_s
        return "" if self.uri.nil?
        "URI:#{self.uri}"
      end
    end

    # Identifies the public key associated with a given certificate.
    # Should be required for "CA" certificates.
    # Reference: Section 4.2.1.2 of RFC3280
    # http://tools.ietf.org/html/rfc3280#section-4.2.1.2
    class SubjectKeyIdentifier
      include ExtensionAPI
      def openssl_identifier
        "subjectKeyIdentifier"
      end

      def to_s
        "hash"
      end
    end

    # Used to identify the keypair used to sign CRLs.
    # Reference: Section 5.2.1 of RFC3280
    # http://tools.ietf.org/html/rfc3280#section-5.2.1
    class AuthorityKeyIdentifier
      include ExtensionAPI

      def openssl_identifier
        "authorityKeyIdentifier"
      end

      def to_s
        "keyid,issuer"
      end
    end

    # Specifies how to access CA information and services for the CA that
    # issued this certificate.
    # Generally used to specify OCSP servers.
    # Reference: Section 4.2.2.1 of RFC3280
    # http://tools.ietf.org/html/rfc3280#section-4.2.2.1
    class AuthorityInfoAccess
      include ExtensionAPI

      attr_accessor :ocsp

      def initialize
        self.ocsp = []
      end

      def openssl_identifier
        "authorityInfoAccess"
      end

      def to_s
        return "" if self.ocsp.empty?
        "OCSP;URI:#{self.ocsp}"
      end
    end

    # Specifies the allowed usage purposes of the keypair specified in this certificate.
    # Reference: Section 4.2.1.3 of RFC3280
    # http://tools.ietf.org/html/rfc3280#section-4.2.1.3
    class KeyUsage
      include ExtensionAPI

      attr_accessor :usage

      def initialize
        self.usage = ["digitalSignature", "nonRepudiation"]
      end

      def openssl_identifier
        "keyUsage"
      end

      def to_s
        "#{self.usage.join(',')}"
      end
    end

    # Specifies even more allowed usages in addition to what is specified in
    # the Key Usage extension.
    # Reference: Section 4.2.1.13 of RFC3280
    # http://tools.ietf.org/html/rfc3280#section-4.2.1.13
    class ExtendedKeyUsage
      include ExtensionAPI

      attr_accessor :usage

      def initialize
        self.usage = ["serverAuth","clientAuth"]
      end

      def openssl_identifier
        "extendedKeyUsage"
      end

      def to_s
        "#{self.usage.join(',')}"
      end
    end

    # Specifies additional "names" for which this certificate is valid.
    # Reference: Section 4.2.1.7 of RFC3280
    # http://tools.ietf.org/html/rfc3280#section-4.2.1.7
    class SubjectAlternativeName
      include ExtensionAPI

      attr_accessor :uris, :dns_names, :ips, :emails

      def initialize
        self.uris = []
        self.dns_names = []
        self.ips = []
        self.emails = []
      end

      def uris=(value)
        raise "URIs must be an array" unless value.is_a?(Array)
        @uris = value
      end

      def dns_names=(value)
        raise "DNS names must be an array" unless value.is_a?(Array)
        @dns_names = value
      end

      def ips=(value)
        raise "IPs must be an array" unless value.is_a?(Array)
        @ips = value
      end

      def emails=(value)
        raise "Emails must be an array" unless value.is_a?(Array)
        @emails = value
      end

      def openssl_identifier
        "subjectAltName"
      end

      def to_s
        res =  self.uris.map {|u| "URI:#{u}" }
        res += self.dns_names.map {|d| "DNS:#{d}" }
        res += self.ips.map {|i| "IP:#{i}" }
        res += self.emails.map {|i| "EMAIL:#{i}" }

        return res.join(',')
      end
    end

    class CertificatePolicies
      include ExtensionAPI

      attr_accessor :policy_identifier
      attr_accessor :cps_uris
      ##User notice
      attr_accessor :explicit_text
      attr_accessor :organization
      attr_accessor :notice_numbers

      def initialize
        @contains_data = false
      end


      def openssl_identifier
        "certificatePolicies"
      end

      def user_notice=(value={})
        value.keys.each do |key|
          self.send("#{key}=".to_sym, value[key])
        end
      end

      def config_extensions
        config_extension = {}
        custom_policies = {}
        notice = {}
        unless self.policy_identifier.nil?
          custom_policies["policyIdentifier"] = self.policy_identifier
        end

        if !self.cps_uris.nil? and self.cps_uris.is_a?(Array)
          self.cps_uris.each_with_index do |cps_uri,i|
            custom_policies["CPS.#{i}"] = cps_uri
          end
        end

        unless self.explicit_text.nil?
          notice["explicitText"] = self.explicit_text
        end

        unless self.organization.nil?
          notice["organization"] = self.organization
        end

        unless self.notice_numbers.nil?
          notice["noticeNumbers"] = self.notice_numbers
        end

        if notice.keys.size > 0
          custom_policies["userNotice.1"] = "@notice"
          config_extension["notice"] = notice
        end

        if custom_policies.keys.size > 0
          config_extension["custom_policies"] = custom_policies
          @contains_data = true
        end

        config_extension
      end

      def to_s
        return "" unless @contains_data
        "ia5org,@custom_policies"
      end
    end

  end
end
