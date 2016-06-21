module CertificateAuthority
  class CertificateRevocationList
    include Validations

    attr_accessor :certificates
    attr_accessor :parent
    attr_accessor :crl_body
    attr_accessor :next_update
    attr_accessor :last_update_skew_seconds

    def validate
      errors.add :next_update, "Next update must be a positive value" if self.next_update < 0
      errors.add :parent, "A parent entity must be set" if self.parent.nil?
    end

    def initialize
      self.certificates = []
      self.next_update = 60 * 60 * 4 # 4 hour default
      self.last_update_skew_seconds = 0
    end

    def <<(revocable)
      case revocable
      when Revocable
        raise "Only revoked entities can be added to a CRL" unless revocable.revoked?
        self.certificates << revocable
      when OpenSSL::X509::Certificate
        raise "Not implemented yet"
      else
        raise "#{revocable.class} cannot be included in a CRL"
      end
    end

    def sign!(signing_profile={})
      raise "No parent entity has been set!" if self.parent.nil?
      raise "Invalid CRL" unless self.valid?

      revocations = self.certificates.collect do |revocable|
        revocation = OpenSSL::X509::Revoked.new

        ## We really just need a serial number, now we have to dig it out
        case revocable
        when Certificate
          x509_cert = OpenSSL::X509::Certificate.new(revocable.to_pem)
          revocation.serial = x509_cert.serial
        when SerialNumber
          revocation.serial = revocable.number
        end
        revocation.time = revocable.revoked_at
        revocation
      end

      crl = OpenSSL::X509::CRL.new
      revocations.each do |revocation|
        crl.add_revoked(revocation)
      end

      crl.version = 1
      crl.last_update = Time.now - self.last_update_skew_seconds
      crl.next_update = Time.now + self.next_update

      signing_cert = OpenSSL::X509::Certificate.new(self.parent.to_pem)
      if signing_profile["digest"].nil?
        digest = OpenSSL::Digest.new("SHA512")
      else
        digest = OpenSSL::Digest.new(signing_profile["digest"])
      end
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
