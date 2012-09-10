module CertificateAuthority
  class SigningRequest
    attr_accessor :distinguished_name
    attr_accessor :raw_body

    def self.from_x509_csr(raw_csr)
      csr = SigningRequest.new
      openssl_csr = OpenSSL::X509::Request.new(raw_csr)
      csr.distinguished_name = DistinguishedName.from_openssl openssl_csr.subject
      csr.raw_body = csr
      csr
    end
  end
end
