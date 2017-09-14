module CertificateAuthority
  module Extensions
    module ExtensionAPI
      def to_s
        raise "Implementation required"
      end

      def self.parse(value, critical)
        raise "Implementation required"
      end

      def config_extensions
        {}
      end

      def openssl_identifier
        raise "Implementation required"
      end

      def ==(value)
        raise "Implementation required"
      end
    end

    # Specifies whether an X.509v3 certificate can act as a CA, signing other
    # certificates to be verified. If set, a path length constraint can also be
    # specified.
    # Reference: Section 4.2.1.10 of RFC3280
    # http://tools.ietf.org/html/rfc3280#section-4.2.1.10
    class BasicConstraints
      OPENSSL_IDENTIFIER = "basicConstraints"

      include ExtensionAPI
      include Validations

      attr_accessor :critical
      attr_accessor :ca
      attr_accessor :path_len

      def validate
        unless [true, false].include? self.critical
          errors.add :critical, 'must be true or false'
        end
        unless [true, false].include? self.ca
          errors.add :ca, 'must be true or false'
        end
      end

      def initialize
        @critical = false
        @ca = false
      end

      def openssl_identifier
        OPENSSL_IDENTIFIER
      end

      def is_ca?
        @ca
      end

      def path_len=(value)
        raise "path_len must be a non-negative integer" if value < 0 or !value.is_a?(Integer)
        @path_len = value
      end

      def to_s
        res = []
        res << "CA:#{@ca}"
        res << "pathlen:#{@path_len}" unless @path_len.nil?
        res.join(',')
      end

      def ==(o)
        o.class == self.class && o.state == state
      end

      def self.parse(value, critical)
        obj = self.new
        return obj if value.nil?
        obj.critical = critical
        value.split(/,\s*/).each do |v|
          c = v.split(':', 2)
          obj.ca = (c.last.upcase == "TRUE") if c.first == "CA"
          obj.path_len = c.last.to_i if c.first == "pathlen"
        end
        obj
      end

      protected
      def state
        [@critical,@ca,@path_len]
      end
    end

    # Specifies where CRL information be be retrieved. This extension isn't
    # critical, but is recommended for proper CAs.
    # Reference: Section 4.2.1.14 of RFC3280
    # http://tools.ietf.org/html/rfc3280#section-4.2.1.14
    class CrlDistributionPoints
      OPENSSL_IDENTIFIER = "crlDistributionPoints"

      include ExtensionAPI

      attr_accessor :critical
      attr_accessor :uris

      def initialize
        @critical = false
        @uris = []
      end

      def openssl_identifier
        OPENSSL_IDENTIFIER
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

      # This is for legacy support. Technically it can (and probably should)
      # be an array. But if someone is calling the old accessor we shouldn't
      # necessarily break it.
      def uri=(value)
        @uris << value
      end

      def to_s
        res = []
        @uris.each do |uri|
          res << "URI:#{uri}"
        end
        res.join(',')
      end

      def ==(o)
        o.class == self.class && o.state == state
      end

      def self.parse(value, critical)
        obj = self.new
        return obj if value.nil?
        obj.critical = critical
        value.split(/,\s*/).each do |v|
          c = v.split(':', 2)
          obj.uris << c.last if c.first == "URI"
        end
        obj
      end

      protected
      def state
        [@critical,@uri]
      end
    end

    # Identifies the public key associated with a given certificate.
    # Should be required for "CA" certificates.
    # Reference: Section 4.2.1.2 of RFC3280
    # http://tools.ietf.org/html/rfc3280#section-4.2.1.2
    class SubjectKeyIdentifier
      OPENSSL_IDENTIFIER = "subjectKeyIdentifier"

      include ExtensionAPI

      attr_accessor :critical
      attr_accessor :identifier

      def initialize
        @critical = false
        @identifier = "hash"
      end

      def openssl_identifier
        OPENSSL_IDENTIFIER
      end

      def to_s
        res = []
        res << @identifier
        res.join(',')
      end

      def ==(o)
        o.class == self.class && o.state == state
      end

      def self.parse(value, critical)
        obj = self.new
        return obj if value.nil?
        obj.critical = critical
        obj.identifier = value
        obj
      end

      protected
      def state
        [@critical,@identifier]
      end
    end

    # Identifies the public key associated with a given private key.
    # Reference: Section 4.2.1.1 of RFC3280
    # http://tools.ietf.org/html/rfc3280#section-4.2.1.1
    class AuthorityKeyIdentifier
      OPENSSL_IDENTIFIER = "authorityKeyIdentifier"

      include ExtensionAPI

      attr_accessor :critical
      attr_accessor :identifier

      def initialize
        @critical = false
        @identifier = ["keyid", "issuer"]
      end

      def openssl_identifier
        OPENSSL_IDENTIFIER
      end

      def to_s
        res = []
        res += @identifier
        res.join(',')
      end

      def ==(o)
        o.class == self.class && o.state == state
      end

      def self.parse(value, critical)
        obj = self.new
        return obj if value.nil?
        obj.critical = critical
        obj.identifier = value.split(/,\s*/).last.chomp
        obj
      end

      protected
      def state
        [@critical,@identifier]
      end
    end

    # Specifies how to access CA information and services for the CA that
    # issued this certificate.
    # Generally used to specify OCSP servers.
    # Reference: Section 4.2.2.1 of RFC3280
    # http://tools.ietf.org/html/rfc3280#section-4.2.2.1
    class AuthorityInfoAccess
      OPENSSL_IDENTIFIER = "authorityInfoAccess"

      include ExtensionAPI

      attr_accessor :critical
      attr_accessor :ocsp
      attr_accessor :ca_issuers

      def initialize
        @critical = false
        @ocsp = []
        @ca_issuers = []
      end

      def openssl_identifier
        OPENSSL_IDENTIFIER
      end

      def to_s
        res = []
        res += @ocsp.map {|o| "OCSP;URI:#{o}" }
        res += @ca_issuers.map {|c| "caIssuers;URI:#{c}" }
        res.join(',')
      end

      def ==(o)
        o.class == self.class && o.state == state
      end

      def self.parse(value, critical)
        obj = self.new
        return obj if value.nil?
        obj.critical = critical
        value.split("\n").each do |v|
          if v =~ /^OCSP/
            obj.ocsp << v.split.last
          end

          if v =~ /^CA Issuers/
            obj.ca_issuers << v.split.last
          end
        end
        obj
      end

      protected
      def state
        [@critical,@ocsp,@ca_issuers]
      end
    end

    # Specifies the allowed usage purposes of the keypair specified in this certificate.
    # Reference: Section 4.2.1.3 of RFC3280
    # http://tools.ietf.org/html/rfc3280#section-4.2.1.3
    #
    # Note: OpenSSL when parsing an extension will return results in the form
    # 'Digital Signature', but on signing you have to set it to 'digitalSignature'.
    # So copying an extension from an imported cert isn't going to work yet.
    class KeyUsage
      OPENSSL_IDENTIFIER = "keyUsage"

      include ExtensionAPI

      attr_accessor :critical
      attr_accessor :usage

      def initialize
        @critical = false
        @usage = ["digitalSignature", "nonRepudiation"]
      end

      def openssl_identifier
        OPENSSL_IDENTIFIER
      end

      def to_s
        res = []
        res += @usage
        res.join(',')
      end

      def ==(o)
        o.class == self.class && o.state == state
      end

      def self.parse(value, critical)
        obj = self.new
        return obj if value.nil?
        obj.critical = critical
        obj.usage = value.split(/,\s*/)
        obj
      end

      protected
      def state
        [@critical,@usage]
      end
    end

    # Specifies even more allowed usages in addition to what is specified in
    # the Key Usage extension.
    # Reference: Section 4.2.1.13 of RFC3280
    # http://tools.ietf.org/html/rfc3280#section-4.2.1.13
    class ExtendedKeyUsage
      OPENSSL_IDENTIFIER = "extendedKeyUsage"

      include ExtensionAPI

      attr_accessor :critical
      attr_accessor :usage

      def initialize
        @critical = false
        @usage = ["serverAuth"]
      end

      def openssl_identifier
        OPENSSL_IDENTIFIER
      end

      def to_s
        res = []
        res += @usage
        res.join(',')
      end

      def ==(o)
        o.class == self.class && o.state == state
      end

      def self.parse(value, critical)
        obj = self.new
        return obj if value.nil?
        obj.critical = critical
        obj.usage = value.split(/,\s*/)
        obj
      end

      protected
      def state
        [@critical,@usage]
      end
    end

    # Specifies additional "names" for which this certificate is valid.
    # Reference: Section 4.2.1.7 of RFC3280
    # http://tools.ietf.org/html/rfc3280#section-4.2.1.7
    class SubjectAlternativeName
      OPENSSL_IDENTIFIER = "subjectAltName"

      include ExtensionAPI

      attr_accessor :critical
      attr_accessor :uris, :dns_names, :ips, :emails

      def initialize
        @critical = false
        @uris = []
        @dns_names = []
        @ips = []
        @emails = []
      end

      def openssl_identifier
        OPENSSL_IDENTIFIER
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

      def to_s
        res = []
        res += @uris.map {|u| "URI:#{u}" }
        res += @dns_names.map {|d| "DNS:#{d}" }
        res += @ips.map {|i| "IP:#{i}" }
        res += @emails.map {|i| "email:#{i}" }
        res.join(',')
      end

      def ==(o)
        o.class == self.class && o.state == state
      end

      def self.parse(value, critical)
        obj = self.new
        return obj if value.nil?
        obj.critical = critical
        value.split(/,\s*/).each do |v|
          c = v.split(':', 2)
          obj.uris << c.last if c.first == "URI"
          obj.dns_names << c.last if c.first == "DNS"
          obj.ips << c.last if c.first == "IP"
          obj.emails << c.last if c.first == "EMAIL"
        end
        obj
      end

      protected
      def state
        [@critical,@uris,@dns_names,@ips,@emails]
      end
    end

    class CertificatePolicies
      OPENSSL_IDENTIFIER = "certificatePolicies"

      include ExtensionAPI

      attr_accessor :critical
      attr_accessor :policy_identifier
      attr_accessor :cps_uris
      ##User notice
      attr_accessor :explicit_text
      attr_accessor :organization
      attr_accessor :notice_numbers

      def initialize
        self.critical = false
        @contains_data = false
      end

      def openssl_identifier
        OPENSSL_IDENTIFIER
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
        res = []
        res << "ia5org"
        res += @config_extensions["custom_policies"] unless @config_extensions.nil?
        res.join(',')
      end

      def self.parse(value, critical)
        obj = self.new
        return obj if value.nil?
        obj.critical = critical
        value.split(/,\s*/).each do |v|
          c = v.split(':', 2)
          obj.policy_identifier = c.last if c.first == "policyIdentifier"
          obj.cps_uris << c.last if c.first =~ %r{CPS.\d+}
          # TODO: explicit_text, organization, notice_numbers
        end
        obj
      end
    end

    # DEPRECATED
    # Specifics the purposes for which a certificate can be used.
    # The basicConstraints, keyUsage, and extendedKeyUsage extensions are now used instead.
    # https://www.openssl.org/docs/apps/x509v3_config.html#Netscape_Certificate_Type
    class NetscapeCertificateType
      OPENSSL_IDENTIFIER = "nsCertType"

      include ExtensionAPI

      attr_accessor :critical
      attr_accessor :flags

      def initialize
        self.critical = false
        self.flags = []
      end

      def openssl_identifier
        OPENSSL_IDENTIFIER
      end

      def to_s
        res = []
        res += self.flags
        res.join(',')
      end

      def self.parse(value, critical)
        obj = self.new
        return obj if value.nil?
        obj.critical = critical
        obj.flags = value.split(/,\s*/)
        obj
      end
    end

    # DEPRECATED
    # Contains a comment which will be displayed when the certificate is viewed in some browsers.
    # https://www.openssl.org/docs/apps/x509v3_config.html#Netscape_String_extensions_
    class NetscapeComment
      OPENSSL_IDENTIFIER = "nsComment"

      include ExtensionAPI

      attr_accessor :critical
      attr_accessor :comment

      def initialize
        self.critical = false
      end

      def openssl_identifier
        OPENSSL_IDENTIFIER
      end

      def to_s
        res = []
        res << self.comment if self.comment
        res.join(',')
      end

      def self.parse(value, critical)
        obj = self.new
        return obj if value.nil?
        obj.critical = critical
        obj.comment = value
        obj
      end
    end

  end
end
