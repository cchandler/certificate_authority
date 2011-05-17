module CertificateAuthority
  module KeyMaterial
    def public_key
      raise "Required implementation"
    end
    
    def private_key
      raise "Required implementation"
    end
    
    def is_in_hardware?
      raise "Required implementation"
    end
    
    def is_in_memory?
      raise "Required implementation"
    end
  end
  
  class MemoryKeyMaterial
    include KeyMaterial
    include ActiveModel::Validations
    
    attr_accessor :keypair
    attr_accessor :private_key
    attr_accessor :public_key
    
    def initialize
    end
    
    validates_each :private_key do |record, attr, value|
        record.errors.add :private_key, "cannot be blank" if record.private_key.nil?
    end
    validates_each :public_key do |record, attr, value|
      record.errors.add :public_key, "cannot be blank" if record.public_key.nil?
    end
        
    def is_in_hardware?
      false
    end
    
    def is_in_memory?
      true
    end
    
    def generate_key(modulus_bits=2048)
      self.keypair = OpenSSL::PKey::RSA.new(modulus_bits)
      self.private_key = keypair
      self.public_key = keypair.public_key
      self.keypair
    end
    
    def private_key
      @private_key
    end
    
    def public_key
      @public_key
    end
    
  end
end