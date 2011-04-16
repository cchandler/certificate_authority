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
    end#Basic Contraints
    
    class CrlDistributionPoints
      include ExtensionAPI
      def openssl_identifier
        "crlDistributionPoints"
      end
      
      def to_s
        "URI:http://youFillThisout.com"
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
      def openssl_identifier
        "authorityInfoAccess"
      end
      
      def to_s
        "OCSP;URI:http://youFillThisOut/ocsp/"
      end
    end
    
    class KeyUsage
      include ExtensionAPI
      def openssl_identifier
        "keyUsage"
      end
      
      def to_s
        "digitalSignature,nonRepudiation"
      end
    end
    
    class ExtendedKeyUsage
      include ExtensionAPI
      def openssl_identifier
        "extendedKeyUsage"
      end
      
      def to_s
        "serverAuth,clientAuth"
      end
    end
    
    class SubjectAlternativeName
      include ExtensionAPI
      def openssl_identifier
        "subjectAltName"
      end
      
      def to_s
        "URI:http://subdomains.youFillThisOut/"
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