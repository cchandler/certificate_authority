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

    # @return [Boolean]
    def is_in_hardware?
      false
    end

    # @return [Boolean]
    def is_in_memory?
      true
    end

    # @param modulus_bits [Integer] number of bits to generate the key with
    # @return [OpenSSL::Pkey::RSA]
    def generate_key(modulus_bits=2048)
      self.keypair = OpenSSL::PKey::RSA.new(modulus_bits)
      self.private_key = keypair
      self.public_key = keypair.public_key
      self.keypair
    end

    # @return [OpenSSL::Pkey::RSA]
    def private_key
      @private_key
    end

    # @return [OpenSSL::Pkey::RSA]
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
    attr_reader :csr # @return [OpenSSL::X509::Request,OpenSSL::Netscape::SPKI]
    attr_reader :certificate # @return [CertificateAuthority::Certificate]

    # @param request [OpenSSL::X508::Request,OpenSSL::Netscape::SPKI,String] a signing request
    def initialize(request=nil)
      if request.is_a?(OpenSSL::X509::Request) || request.is_a?(OpenSSL::Netscape::SPKI)
        @csr = request
        raise "Invalid certificate signing request" unless @csr.verify(@csr.public_key)
        self.public_key = @csr.public_key
      end
    end

    # Given a root certificate and a key, will generate a signed certificate
    # @param root_cert [CertificateAuthority::Certificate] the parent certificate (CA)
    # @param key [OpenSSL::Pkey::RSA] the private key to sign with
    # @param serial_number [Integer] the serial number for the generated certificate
    # @param options [Hash{:dn => CertificateAuthority::DistinguishedName, :algorithm => OpenSSL::Digest, :not_after => Time}] :dn is required for SPKAC signing
    # @return [CertificateAuthority::Certificate] A signed certificate instance
    def sign_and_certify(root_cert, key, serial_number, options = {})
      if csr.is_a? OpenSSL::Netscape::SPKI
        raise "Must pass :dn in options to generate certificates for OpenSSL::Netscape::SPKI requests" unless options[:dn]
      end
      algorithm = options[:algorithm] || OpenSSL::Digest::SHA1.new
      cert = OpenSSL::X509::Certificate.new
      if options[:dn]
        cert.subject = options[:dn].to_x509_name
      else
        cert.subject = csr.subject
      end
      cert.public_key = public_key
      cert.not_before = Time.now
      cert.not_after = options[:not_after] || (Time.now + 100000000)
      cert.issuer = root_cert.subject.to_x509_name
      cert.serial = serial_number
      cert.sign key, algorithm
      @certificate = CertificateAuthority::Certificate.from_openssl cert
    end

    # @return [Boolean]
    def is_in_hardware?
      false
    end

    # @return [Boolean]
    def is_in_memory?
      true
    end

    # @return [NilClass]
    def private_key
      nil
    end

    # @return [OpenSSL::Pkey::RSA]
    def public_key
      @public_key
    end
  end
end
