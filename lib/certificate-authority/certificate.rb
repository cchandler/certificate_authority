module CertificateAuthority
  class Certificate
    include SigningEntity
    
    include ActiveModel::Validations
    
    attr_accessor :distinguished_name
    attr_accessor :serial_number
    attr_accessor :key_material
    attr_accessor :not_before
    attr_accessor :not_after
    attr_accessor :openssl_body
    
    alias :subject :distinguished_name #Same thing as the DN
    
    attr_accessor :parent
    
    validate do |certificate|
      errors.add :base, "Distinguished name must be valid" unless distinguished_name.valid?
      errors.add :base, "Key material name must be valid" unless key_material.valid?
    end
    
    def initialize
      self.distinguished_name = DistinguishedName.new
      self.serial_number = SerialNumber.new
      self.key_material = KeyMaterial.new
      self.not_before = Time.now
      self.not_after = Time.now + 60 * 60 * 24 * 365 #One year
      self.parent = self
      self.signing_entity = true
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
      
      digest = OpenSSL::Digest::Digest.new("SHA1")
      self.openssl_body = openssl_cert.sign(parent.key_material.private_key,digest)
      self.openssl_body
    end
    
    def to_pem
      throw "Certificate has no signed body" if self.openssl_body.nil?
      self.openssl_body.to_pem
    end
    
  end
end