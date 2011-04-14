module CertificateAuthority
  class Certificate
    include SigningEntity
    
    attr_accessor :distinguished_name
    attr_accessor :serial_number
    attr_accessor :key_material
    attr_accessor :not_before
    attr_accessor :not_after
    
    alias :subject :distinguished_name #Same thing as the DN
    
    attr_accessor :parent
    
    def initialize()
      self.distinguished_name = DistinguishedName.new
      self.serial_number = SerialNumber.new
      self.key_material = KeyMaterial.new
      self.not_before = Time.now
      self.not_after = Time.now + 60 * 60 * 24 * 365
      self.parent = self
      self.signing_entity = true
    end
    
  end
end