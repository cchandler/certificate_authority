module CertificateAuthority
  class Certificate
    include Validations
    include Revocable

    attr_accessor :distinguished_name
    attr_accessor :serial_number
    attr_accessor :key_material
    attr_accessor :not_before
    attr_accessor :not_after
    attr_accessor :extensions
    attr_accessor :openssl_body

    alias :subject :distinguished_name #Same thing as the DN

    attr_accessor :parent

    def validate
      errors.add :base, "Distinguished name must be valid" unless distinguished_name.valid?
      errors.add :base, "Key material must be valid" unless key_material.valid?
      errors.add :base, "Serial number must be valid" unless serial_number.valid?
      errors.add :base, "Extensions must be valid" unless extensions.each do |item|
        unless item.respond_to?(:valid?)
          true
        else
          item.valid?
        end
      end
    end

    def initialize
      self.distinguished_name = DistinguishedName.new
      self.serial_number = SerialNumber.new
      self.key_material = MemoryKeyMaterial.new
      self.not_before = Date.today.utc
      self.not_after = Date.today.advance(:years => 1).utc
      self.parent = self
      self.extensions = load_extensions()

      self.signing_entity = false

    end

=begin
    def self.from_openssl openssl_cert
      unless openssl_cert.is_a? OpenSSL::X509::Certificate
        raise "Can only construct from an OpenSSL::X509::Certificate"
      end

      certificate = Certificate.new
      # Only subject, key_material, and body are used for signing
      certificate.distinguished_name = DistinguishedName.from_openssl openssl_cert.subject
      certificate.key_material.public_key = openssl_cert.public_key
      certificate.openssl_body = openssl_cert
      certificate.serial_number.number = openssl_cert.serial.to_i
      certificate.not_before = openssl_cert.not_before
      certificate.not_after = openssl_cert.not_after
      # TODO extensions
      certificate
    end
=end

    def sign!(signing_profile={})
      raise "Invalid certificate #{self.errors.full_messages}" unless valid?
      merge_profile_with_extensions(signing_profile)

      openssl_cert = OpenSSL::X509::Certificate.new
      openssl_cert.version = 2
      openssl_cert.not_before = self.not_before
      openssl_cert.not_after = self.not_after
      openssl_cert.public_key = self.key_material.public_key

      openssl_cert.serial = self.serial_number.number

      openssl_cert.subject = self.distinguished_name.to_x509_name
      openssl_cert.issuer = parent.distinguished_name.to_x509_name

      require 'tempfile'
      t = Tempfile.new("bullshit_conf")
      ## The config requires a file even though we won't use it
      openssl_config = OpenSSL::Config.new(t.path)

      factory = OpenSSL::X509::ExtensionFactory.new
      factory.subject_certificate = openssl_cert

      #NB: If the parent doesn't have an SSL body we're making this a self-signed cert
      if parent.openssl_body.nil?
        factory.issuer_certificate = openssl_cert
      else
        factory.issuer_certificate = parent.openssl_body
      end

      self.extensions.keys.each do |k|
        config_extensions = extensions[k].config_extensions
        openssl_config = merge_options(openssl_config,config_extensions)
      end

      # p openssl_config.sections

      factory.config = openssl_config

      # Order matters: e.g. for self-signed, subjectKeyIdentifier must come before authorityKeyIdentifier
      self.extensions.keys.sort{|a,b| b<=>a}.each do |k|
        e = extensions[k]
        next if e.to_s.nil? or e.to_s == "" ## If the extension returns an empty string we won't include it
        ext = factory.create_ext(e.openssl_identifier, e.to_s, e.critical)
        openssl_cert.add_extension(ext)
      end

      if signing_profile["digest"].nil?
        digest = OpenSSL::Digest.new("SHA512")
      else
        digest = OpenSSL::Digest.new(signing_profile["digest"])
      end

      self.openssl_body = openssl_cert.sign(parent.key_material.private_key, digest)
    ensure
      t.close! if t # We can get rid of the ridiculous temp file
    end

    def is_signing_entity?
      self.extensions["basicConstraints"].ca
    end

    def signing_entity=(signing)
      self.extensions["basicConstraints"].ca = signing
    end

    def revoked?
      !self.revoked_at.nil?
    end

    def to_pem
      raise "Certificate has no signed body" if self.openssl_body.nil?
      self.openssl_body.to_pem
    end

    def to_csr
      csr = SigningRequest.new
      csr.distinguished_name = self.distinguished_name
      csr.key_material = self.key_material
      factory = OpenSSL::X509::ExtensionFactory.new
      exts = []
      self.extensions.keys.each do |k|
        ## Don't copy over key identifiers for CSRs
        next if k == "subjectKeyIdentifier" || k == "authorityKeyIdentifier"
        e = extensions[k]
        ## If the extension returns an empty string we won't include it
        next if e.to_s.nil? or e.to_s == ""
        exts << factory.create_ext(e.openssl_identifier, e.to_s, e.critical)
      end
      attrval = OpenSSL::ASN1::Set([OpenSSL::ASN1::Sequence(exts)])
      attrs = [
        OpenSSL::X509::Attribute.new("extReq", attrval),
        OpenSSL::X509::Attribute.new("msExtReq", attrval)
      ]
      csr.attributes = attrs
      csr
    end

    def self.from_x509_cert(raw_cert)
      openssl_cert = OpenSSL::X509::Certificate.new(raw_cert)
      Certificate.from_openssl(openssl_cert)
    end

    def is_root_entity?
      self.parent == self && is_signing_entity?
    end

    def is_intermediate_entity?
      (self.parent != self) && is_signing_entity?
    end

    private

    def merge_profile_with_extensions(signing_profile={})
      return self.extensions if signing_profile["extensions"].nil?
      signing_config = signing_profile["extensions"]
      signing_config.keys.each do |k|
        extension = self.extensions[k]
        items = signing_config[k]
        items.keys.each do |profile_item_key|
          if extension.respond_to?("#{profile_item_key}=".to_sym)
            if k == 'subjectAltName' && profile_item_key == 'emails'
              items[profile_item_key].map do |email|
                if email == 'email:copy'
                  fail "no email address provided for subject: #{subject.to_x509_name}" unless subject.email_address
                  "email:#{subject.email_address}"
                else
                  email
                end
              end
            end
            extension.send("#{profile_item_key}=".to_sym, items[profile_item_key] )
          else
            p "Tried applying '#{profile_item_key}' to #{extension.class} but it doesn't respond!"
          end
        end
      end
    end

    # Enumeration of the extensions. Not the worst option since
    # the likelihood of these needing to be updated is low at best.
    EXTENSIONS = [
        CertificateAuthority::Extensions::BasicConstraints,
        CertificateAuthority::Extensions::CrlDistributionPoints,
        CertificateAuthority::Extensions::SubjectKeyIdentifier,
        CertificateAuthority::Extensions::AuthorityKeyIdentifier,
        CertificateAuthority::Extensions::AuthorityInfoAccess,
        CertificateAuthority::Extensions::KeyUsage,
        CertificateAuthority::Extensions::ExtendedKeyUsage,
        CertificateAuthority::Extensions::SubjectAlternativeName,
        CertificateAuthority::Extensions::CertificatePolicies
    ]

    def load_extensions
      extension_hash = {}

      EXTENSIONS.each do |klass|
        extension = klass.new
        extension_hash[extension.openssl_identifier] = extension
      end

      extension_hash
    end

    def merge_options(config,hash)
      hash.keys.each do |k|
        config[k] = hash[k]
      end
      config
    end

    def self.from_openssl openssl_cert
      unless openssl_cert.is_a? OpenSSL::X509::Certificate
        raise "Can only construct from an OpenSSL::X509::Certificate"
      end

      certificate = Certificate.new
      # Only subject, key_material, and body are used for signing
      certificate.distinguished_name = DistinguishedName.from_openssl openssl_cert.subject
      certificate.key_material.public_key = openssl_cert.public_key
      certificate.openssl_body = openssl_cert
      certificate.serial_number.number = openssl_cert.serial.to_i
      certificate.not_before = openssl_cert.not_before
      certificate.not_after = openssl_cert.not_after
      EXTENSIONS.each do |klass|
        _,v,c = (openssl_cert.extensions.detect { |e| e.to_a.first == klass::OPENSSL_IDENTIFIER } || []).to_a
        certificate.extensions[klass::OPENSSL_IDENTIFIER] = klass.parse(v, c) if v
      end

      certificate
    end

  end
end
