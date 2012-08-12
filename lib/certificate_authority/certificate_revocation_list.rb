module CertificateAuthority
  class CertificateRevocationList
    include ActiveModel::Validations

    attr_accessor :certificates
    attr_accessor :parent
    attr_accessor :crl_body
    attr_accessor :next_update

    validate do |crl|
      errors.add :next_update, "Next update must be a positive value" if crl.next_update < 0
      errors.add :parent, "A parent entity must be set" if crl.parent.nil?
    end

    def initialize
      self.certificates = []
      self.next_update = 60 * 60 * 4 # 4 hour default
    end

    def <<(cert)
      raise "Only revoked certificates can be added to a CRL" unless cert.revoked?
      self.certificates << cert
    end

    def sign!
      raise "No parent entity has been set!" if self.parent.nil?
      raise "Invalid CRL" unless self.valid?

      revocations = self.certificates.collect do |certificate|
        revocation = OpenSSL::X509::Revoked.new
        x509_cert = OpenSSL::X509::Certificate.new(certificate.to_pem)
        revocation.serial = x509_cert.serial
        revocation.time = certificate.revoked_at
        revocation
      end

      crl = OpenSSL::X509::CRL.new
      revocations.each do |revocation|
        crl.add_revoked(revocation)
      end

      crl.version = 1
      crl.last_update = Time.now
      crl.next_update = Time.now + self.next_update

      signing_cert = OpenSSL::X509::Certificate.new(self.parent.to_pem)
      digest = OpenSSL::Digest::Digest.new("SHA512")
      crl.issuer = signing_cert.subject
      self.crl_body = crl.sign(self.parent.key_material.private_key, digest)

      self.crl_body
    end

    def to_pem
      raise "No signed CRL body" if self.crl_body.nil?
      self.crl_body.to_pem
    end
  end#CertificateRevocationList
end
