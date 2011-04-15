module CertificateAuthority
  class Certificate
    include SigningEntity
    include ActiveModel::Validations
    
    attr_accessor :distinguished_name
    attr_accessor :serial_number
    attr_accessor :key_material
    attr_accessor :not_before
    attr_accessor :not_after
    attr_accessor :revoked_at
    attr_accessor :extensions
    attr_accessor :openssl_body
    
    alias :subject :distinguished_name #Same thing as the DN
    
    attr_accessor :parent
    
    validate do |certificate|
      errors.add :base, "Distinguished name must be valid" unless distinguished_name.valid?
      errors.add :base, "Key material name must be valid" unless key_material.valid?
      errors.add :base, "Extensions must be valid" unless extensions.each {|item| item.valid? }
    end
    
    def initialize
      self.distinguished_name = DistinguishedName.new
      self.serial_number = SerialNumber.new
      self.key_material = MemoryKeyMaterial.new
      self.not_before = Time.now
      self.not_after = Time.now + 60 * 60 * 24 * 365 #One year
      self.parent = self
      self.signing_entity = false
      self.extensions = []
    end
    
    def sign!
      throw "Invalid certificate" unless valid?
      
      openssl_cert = OpenSSL::X509::Certificate.new
      openssl_cert.version    = 2
      openssl_cert.not_before = self.not_before
      openssl_cert.not_after = self.not_after
      openssl_cert.public_key = self.key_material.public_key
      
      openssl_cert.subject = self.distinguished_name.to_x509_name
      openssl_cert.issuer = parent.distinguished_name.to_x509_name
      
      factory = OpenSSL::X509::ExtensionFactory.new
      factory.subject_certificate = openssl_cert
      
      #NB: If the parent doesn't have an SSL body we're making this a self-signed cert
      if parent.openssl_body.nil?
        factory.issuer_certificate = openssl_cert
      else
        factory.issuer_certificate = parent.openssl_body
      end
      
      basic_constraints = CertificateAuthority::Extensions::BasicContraints.new
      basic_constraints.ca = is_signing_entity?
      self.extensions << basic_constraints
      
      crl_distribution_points = CertificateAuthority::Extensions::CrlDistributionPoints.new
      self.extensions << crl_distribution_points
      
      subject_key_identifier = CertificateAuthority::Extensions::SubjectKeyIdentifier.new
      self.extensions << subject_key_identifier
      
      authority_key_identifier = CertificateAuthority::Extensions::AuthorityKeyIdentifier.new
      self.extensions << authority_key_identifier
      
      authority_info_access = CertificateAuthority::Extensions::AuthorityInfoAccess.new
      self.extensions << authority_info_access
      
      key_usage = CertificateAuthority::Extensions::KeyUsage.new
      self.extensions << key_usage
      
      extended_key_usage = CertificateAuthority::Extensions::ExtendedKeyUsage.new
      self.extensions << extended_key_usage
      
      subject_alternative_name = CertificateAuthority::Extensions::SubjectAlternativeName.new
      self.extensions << subject_alternative_name
      
      self.extensions.each do |e|
        ext = factory.create_ext(e.openssl_identifier, e.to_s)
        openssl_cert.add_extension(ext)
      end
      
      digest = OpenSSL::Digest::Digest.new("SHA512")
      self.openssl_body = openssl_cert.sign(parent.key_material.private_key,digest)
      self.openssl_body
    end
    
    def revoked?
      !self.revoked_at.nil?
    end
    
    def to_pem
      throw "Certificate has no signed body" if self.openssl_body.nil?
      self.openssl_body.to_pem
    end
    
  end
end