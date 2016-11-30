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

    def self.from_x509_key_pair(pair,password=nil)
      if password.nil?
        key = OpenSSL::PKey::RSA.new(pair)
      else
        key = OpenSSL::PKey::RSA.new(pair,password)
      end
      mem_key = MemoryKeyMaterial.new
      mem_key.public_key = key.public_key
      mem_key.private_key = key
      mem_key
    end

    def self.from_x509_public_key(public_key_pem)
      key = OpenSSL::PKey::RSA.new(public_key_pem)
      signing_request_key = SigningRequestKeyMaterial.new
      signing_request_key.public_key = key.public_key
      signing_request_key
    end
  end

  class MemoryKeyMaterial
    include KeyMaterial
    include Validations

    attr_accessor :keypair
    attr_accessor :private_key
    attr_accessor :public_key

    def initialize
    end

    def validate
      if private_key.nil?
        errors.add :private_key, "cannot be blank"
      end
      if public_key.nil?
        errors.add :public_key, "cannot be blank"
      end
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

  class SigningRequestKeyMaterial
    include KeyMaterial
    include Validations

    def validate
      errors.add :public_key, "cannot be blank" if public_key.nil?
    end

    attr_accessor :public_key

    def initialize(request=nil)
      if request.is_a? OpenSSL::X509::Request
        raise "Invalid certificate signing request" unless request.verify request.public_key
        self.public_key = request.public_key
      end
    end

    def is_in_hardware?
      false
    end

    def is_in_memory?
      true
    end

    def private_key
      nil
    end

    def public_key
      @public_key
    end
  end
end
