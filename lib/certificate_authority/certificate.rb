module CertificateAuthority
  class Certificate
    # include SigningEntity
    include ActiveModel::Validations

    attr_accessor :distinguished_name
    attr_accessor :serial_number
    attr_accessor :key_material
    attr_accessor :not_before
    attr_accessor :not_after
    attr_accessor :revoked_at
    attr_accessor :extensions
    attr_accessor :openssl_body

    alias :subject :distinguished_name #Same thing as the DN

    attr_accessor :parent

    validate do |certificate|
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
      self.not_before = Time.now
      self.not_after = Time.now + 60 * 60 * 24 * 365 #One year
      self.parent = self
      self.extensions = load_extensions()

      self.signing_entity = false

    end

    def sign!(signing_profile={})
      raise "Invalid certificate #{self.errors.full_messages}" unless valid?
      merge_profile_with_extensions(signing_profile)

      openssl_cert = OpenSSL::X509::Certificate.new
      openssl_cert.version    = 2
      openssl_cert.not_before = self.not_before
      openssl_cert.not_after = self.not_after
      openssl_cert.public_key = self.key_material.public_key

      openssl_cert.serial = self.serial_number.number

      openssl_cert.subject = self.distinguished_name.to_x509_name
      openssl_cert.issuer = parent.distinguished_name.to_x509_name

      require 'tempfile'
      t = Tempfile.new("bullshit_conf")
      # t = File.new("/tmp/openssl.cnf")
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
        ext = factory.create_ext(e.openssl_identifier, e.to_s)
        openssl_cert.add_extension(ext)
      end

      if signing_profile["digest"].nil?
        digest = OpenSSL::Digest::Digest.new("SHA512")
      else
        digest = OpenSSL::Digest::Digest.new(signing_profile["digest"])
      end
      self.openssl_body = openssl_cert.sign(parent.key_material.private_key,digest)
      t.close! if t.is_a?(Tempfile)# We can get rid of the ridiculous temp file
      self.openssl_body
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
            extension.send("#{profile_item_key}=".to_sym, items[profile_item_key] )
          else
            p "Tried applying '#{profile_item_key}' to #{extension.class} but it doesn't respond!"
          end
        end
      end
    end

    def load_extensions
      extension_hash = {}

      temp_extensions = []
      basic_constraints = CertificateAuthority::Extensions::BasicContraints.new
      temp_extensions << basic_constraints
      crl_distribution_points = CertificateAuthority::Extensions::CrlDistributionPoints.new
      temp_extensions << crl_distribution_points
      subject_key_identifier = CertificateAuthority::Extensions::SubjectKeyIdentifier.new
      temp_extensions << subject_key_identifier
      authority_key_identifier = CertificateAuthority::Extensions::AuthorityKeyIdentifier.new
      temp_extensions << authority_key_identifier
      authority_info_access = CertificateAuthority::Extensions::AuthorityInfoAccess.new
      temp_extensions << authority_info_access
      key_usage = CertificateAuthority::Extensions::KeyUsage.new
      temp_extensions << key_usage
      extended_key_usage = CertificateAuthority::Extensions::ExtendedKeyUsage.new
      temp_extensions << extended_key_usage
      subject_alternative_name = CertificateAuthority::Extensions::SubjectAlternativeName.new
      temp_extensions << subject_alternative_name
      certificate_policies = CertificateAuthority::Extensions::CertificatePolicies.new
      temp_extensions << certificate_policies

      temp_extensions.each do |extension|
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
      # TODO extensions
      certificate
    end

  end
end
