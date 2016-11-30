module CertificateAuthority
  class Pkcs11KeyMaterial
    include KeyMaterial

    attr_accessor :engine
    attr_accessor :token_id
    attr_accessor :pkcs11_lib
    attr_accessor :openssl_pkcs11_engine_lib
    attr_accessor :pin

    def initialize(attributes = {})
      @attributes = attributes
      initialize_engine
    end

    def is_in_hardware?
      true
    end

    def is_in_memory?
      false
    end

    def generate_key(modulus_bits=1024)
      puts "Key generation is not currently supported in hardware"
      nil
    end

    def private_key
      initialize_engine
      self.engine.load_private_key(self.token_id)
    end

    def public_key
      initialize_engine
      self.engine.load_public_key(self.token_id)
    end

    private

    def initialize_engine
      ## We're going to return early and try again later if params weren't passed in
      ## at initialization.  Any attempt at getting a public/private key will try
      ## again.
      return false if self.openssl_pkcs11_engine_lib.nil? or self.pkcs11_lib.nil?
      return self.engine unless self.engine.nil?
      OpenSSL::Engine.load

      pkcs11 = OpenSSL::Engine.by_id("dynamic") do |e|
        e.ctrl_cmd("SO_PATH",self.openssl_pkcs11_engine_lib)
        e.ctrl_cmd("ID","pkcs11")
        e.ctrl_cmd("LIST_ADD","1")
        e.ctrl_cmd("LOAD")
        e.ctrl_cmd("PIN",self.pin) unless self.pin.nil? or self.pin == ""
        e.ctrl_cmd("MODULE_PATH",self.pkcs11_lib)
      end

      self.engine = pkcs11
      pkcs11
    end

  end
end
