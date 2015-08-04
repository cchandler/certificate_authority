module CertificateAuthority
  class SigningRequest
    attr_accessor :distinguished_name
    attr_accessor :key_material
    attr_accessor :raw_body
    attr_accessor :openssl_csr
    attr_accessor :digest
    attr_accessor :attributes

    def initialize()
      @attributes = []
    end

    # Fake attribute for convenience because adding
    # alternative names on a CSR is remarkably non-trivial.
    def subject_alternative_names=(alt_names)
      raise "alt_names must be an Array" unless alt_names.is_a?(Array)

      factory = OpenSSL::X509::ExtensionFactory.new
      name_list = alt_names.map{|m| "DNS:#{m}"}.join(",")
      ext = factory.create_ext("subjectAltName",name_list,false)
      ext_set = OpenSSL::ASN1::Set([OpenSSL::ASN1::Sequence([ext])])
      attr = OpenSSL::X509::Attribute.new("extReq", ext_set)
      @attributes << attr
    end

    def read_attributes_by_oid(*oids)
      attributes.detect { |a| oids.include?(a.oid) }
    end
    protected :read_attributes_by_oid

    def to_cert
      cert = Certificate.new
      if !@distinguished_name.nil?
        cert.distinguished_name = @distinguished_name
      end
      cert.key_material = @key_material
      if attribute = read_attributes_by_oid('extReq', 'msExtReq')
        set = OpenSSL::ASN1.decode(attribute.value)
        seq = set.value.first
        seq.value.collect { |asn1ext| OpenSSL::X509::Extension.new(asn1ext).to_a }.each do |o, v, c|
         Certificate::EXTENSIONS.each do |klass|
            cert.extensions[klass::OPENSSL_IDENTIFIER] = klass.parse(v, c) if v && klass::OPENSSL_IDENTIFIER == o
          end
        end
      end
      cert
    end

    def to_pem
      to_x509_csr.to_pem
    end

    def to_x509_csr
      raise "Must specify a DN/subject on csr" if @distinguished_name.nil?
      raise "Invalid DN in request" unless @distinguished_name.valid?
      raise "CSR must have key material" if @key_material.nil?
      raise "CSR must include a public key on key material" if @key_material.public_key.nil?
      raise "Need a private key on key material for CSR generation" if @key_material.private_key.nil?

      opensslcsr = OpenSSL::X509::Request.new
      opensslcsr.subject = @distinguished_name.to_x509_name
      opensslcsr.public_key = @key_material.public_key
      opensslcsr.attributes = @attributes unless @attributes.nil?
      opensslcsr.sign @key_material.private_key, OpenSSL::Digest.new(@digest || "SHA512")
      opensslcsr
    end

    def self.from_x509_csr(raw_csr)
      csr = SigningRequest.new
      openssl_csr = OpenSSL::X509::Request.new(raw_csr)
      csr.distinguished_name = DistinguishedName.from_openssl openssl_csr.subject
      csr.raw_body = raw_csr
      csr.openssl_csr = openssl_csr
      csr.attributes = openssl_csr.attributes
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
