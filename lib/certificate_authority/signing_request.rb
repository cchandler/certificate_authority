module CertificateAuthority
  class SigningRequest
    attr_accessor :distinguished_name
    attr_accessor :key_material
    attr_accessor :raw_body
    attr_accessor :openssl_csr

    def to_cert
      cert = Certificate.new
      if !@distinguished_name.nil?
        cert.distinguished_name = @distinguished_name
      end
      cert.key_material = @key_material
      cert
    end

    def to_x509_csr
      raise "Must specify a DN/subject on csr" if @distinguished_name.nil?
      raise "Invalid DN in request" unless @distinguished_name.valid?
      raise "CSR must have key material" if @key_material.nil?
      raise "CSR must include a public key on key material" if @key_material.public_key.nil?
      opensslcsr = OpenSSL::X509::Request.new
      opensslcsr.subject = @distinguished_name.to_x509_name
      opensslcsr.public_key = @key_material.public_key
      opensslcsr
    end

    def self.from_x509_csr(raw_csr)
      csr = SigningRequest.new
      openssl_csr = OpenSSL::X509::Request.new(raw_csr)
      csr.distinguished_name = DistinguishedName.from_openssl openssl_csr.subject
      csr.raw_body = raw_csr
      csr.openssl_csr = openssl_csr
      key_material = SigningRequestKeyMaterial.new
      key_material.public_key = openssl_csr.public_key
      csr.key_material = key_material
      csr
    end

    def self.from_netscape_spkac(raw_spkac)
      openssl_spkac = OpenSSL::Netscape::SPKI.new raw_spkac
      csr = SigningRequest.new
      csr.raw_body = raw_spkac
      key_material = SigningRequestKeyMaterial.new
      key_material.public_key = openssl_spkac.public_key
      csr
    end
  end
end
