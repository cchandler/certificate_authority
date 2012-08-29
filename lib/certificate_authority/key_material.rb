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

  class SigningRequestKeyMaterial
    include KeyMaterial
    include ActiveModel::Validations

    validates_each :public_key do |record, attr, value|
      record.errors.add :public_key, "cannot be blank" if record.public_key.nil?
    end

    attr_accessor :public_key
    attr_reader :csr, :certificate

    def initialize(request=nil)
      if request.is_a?(OpenSSL::X509::Request) || request.is_a?(OpenSSL::Netscape::SPKI)
        @csr = request
        raise "Invalid certificate signing request" unless @csr.verify(@csr.public_key)
        self.public_key = @csr.public_key
      end
    end

    def sign_and_certify(root_cert, key, serial_number, options = {})
      if key.is_a? OpenSSL::Netscape::SPKI
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
