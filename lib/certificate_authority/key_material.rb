module CertificateAuthority
  class KeyMaterial
    include ActiveModel::Validations
    
    attr_accessor :in_memory
    attr_accessor :keypair
    attr_accessor :private_key
    attr_accessor :public_key
    
    def initialize
      self.in_memory = true
      @errors = ActiveModel::Errors.new(self)
    end
    
    validates_each :private_key do |record, attr, value|
        record.errors.add :private_key, "cannot be blank" if record.private_key.nil?
    end
    validates_each :public_key do |record, attr, value|
      record.errors.add :public_key, "cannot be blank" if record.public_key.nil?
    end
        
    def is_in_hardware?
      !self.in_memory
    end
    
    def is_in_memory?
      self.in_memory
    end
    
    def generate_key(modulus_bits=1024)
      self.keypair = OpenSSL::PKey::RSA.new(modulus_bits)
      self.private_key = keypair
      self.public_key = keypair.public_key
      self.keypair
    end
    
    def private_key
      throw "Private key in hardware" if is_in_hardware?
      @private_key
    end
    
    def public_key
      @public_key
    end
    
  end
end