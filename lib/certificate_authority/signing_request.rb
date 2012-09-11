module CertificateAuthority
  class SigningRequest
    attr_accessor :distinguished_name
    attr_accessor :key_material
    attr_accessor :raw_body
    attr_accessor :openssl_csr

    def to_cert
      cert = Certificate.new
      cert.distinguished_name = @distinguished_name
      cert.key_material = @key_material
      cert
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
  end
end
