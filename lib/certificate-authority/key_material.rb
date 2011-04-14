module CertificateAuthority
  class KeyMaterial
    attr_accessor :in_memory
    attr_accessor :keypair
    attr_accessor :private_key
    attr_accessor :public_key
    
    def initialize
      self.in_memory = true
    end
    
    def is_in_hardware?
      !self.in_memory
    end
    
    def is_in_memory?
      self.in_memory
    end
    
    def generate_key(modulus_bits=1024)
      self.keypair = OpenSSL::PKey::RSA.new(modulus_bits)
      self.private_key = keypair.to_pem
      self.public_key = keypair.public_key.to_pem
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