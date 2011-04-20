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
    
    class BasicContraints
      include ExtensionAPI
      include ActiveModel::Validations
      attr_accessor :ca
      validates :ca, :inclusion => [true,false]
      
      def initialize
        self.ca = false
      end
      
      def is_ca?
        self.ca
      end
      
      def openssl_identifier
        "basicConstraints"
      end
      
      def to_s
        "CA:#{self.ca}"
      end
    end
    
    class CrlDistributionPoints
      include ExtensionAPI
      
      attr_accessor :uri
      
      def initialize
        self.uri = "http://moo.crlendPoint.example.com/something.crl"
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
        "URI:#{self.uri}"
      end
    end
    
    class SubjectKeyIdentifier
      include ExtensionAPI
      def openssl_identifier
        "subjectKeyIdentifier"
      end
      
      def to_s
        "hash"
      end
    end
    
    class AuthorityKeyIdentifier
      include ExtensionAPI
      
      def openssl_identifier
        "authorityKeyIdentifier"
      end
      
      def to_s
        "keyid,issuer"
      end
    end
    
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
        "OCSP;URI:#{self.ocsp}"
      end
    end
    
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
    
    class SubjectAlternativeName
      include ExtensionAPI
      
      attr_accessor :uris
      
      def initialize
        self.uris = []
      end
      
      def openssl_identifier
        "subjectAltName"
      end
      
      def config_extensions
        # {"dir_sect" => {"C" => "US", "CN" => "weee.com"}}
        {}
      end
      
      def to_s
        # entries = self.uris.map {|i| "URI:#{i}"}
        # return "" if entries.empty?
        if self.uris.empty?
          return ""
        end
        "URI:#{self.uris.join(',URI:')}"
        # "dirName:dir_sect"
      end
    end
    
    class CertificatePolicies
      include ExtensionAPI
      def openssl_identifier
        "certificatePolicies"
      end
      
      def config_extensions
        {
          "custom_policies" => {"policyIdentifier"=>"1.3.5.8", "CPS.1"=>"http://my.host.name/;", "CPS.2"=>"http://my.your.name/;", "userNotice.1"=>"@notice"},
          "notice" => {"explicitText" => "Explicit Text Here", "organization" => "Organization name", "noticeNumbers" => "1,2,3,4"}
        }
      end
      
      def to_s
        "ia5org,@custom_policies"
      end
    end
    
  end
end