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
      
      def uris=(value)
        raise "URIs must be an array" unless value.is_a?(Array)
        @uris = value
      end
      
      def openssl_identifier
        "subjectAltName"
      end
      
      def to_s
        if self.uris.empty?
          return ""
        end
        "URI:#{self.uris.join(',URI:')}"
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