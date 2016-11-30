module CertificateAuthority
  class DistinguishedName
    include Validations

    def validate
      if self.common_name.nil? || self.common_name.empty?
        errors.add :common_name, 'cannot be blank'
      end
    end

    attr_accessor :common_name
    alias :cn :common_name
    alias :cn= :common_name=

    attr_accessor :locality
    alias :l :locality
    alias :l= :locality=

    attr_accessor :state
    alias :s :state
    alias :st= :state=

    attr_accessor :country
    alias :c :country
    alias :c= :country=

    attr_accessor :organization
    alias :o :organization
    alias :o= :organization=

    attr_accessor :organizational_unit
    alias :ou :organizational_unit
    alias :ou= :organizational_unit=

    attr_accessor :email_address
    alias :emailAddress :email_address
    alias :emailAddress= :email_address=

    attr_accessor :serial_number
    alias :serialNumber :serial_number
    alias :serialNumber= :serial_number=

    def to_x509_name
      raise "Invalid Distinguished Name" unless valid?

      # NB: the capitalization in the strings counts
      name = OpenSSL::X509::Name.new
      name.add_entry("serialNumber", serial_number) unless serial_number.blank?
      name.add_entry("C", country) unless country.blank?
      name.add_entry("ST", state) unless state.blank?
      name.add_entry("L", locality) unless locality.blank?
      name.add_entry("O", organization) unless organization.blank?
      name.add_entry("OU", organizational_unit) unless organizational_unit.blank?
      name.add_entry("CN", common_name)
      name.add_entry("emailAddress", email_address) unless email_address.blank?
      name
    end

    def ==(other)
      # Use the established OpenSSL comparison
      self.to_x509_name() == other.to_x509_name()
    end

    def self.from_openssl openssl_name
      unless openssl_name.is_a? OpenSSL::X509::Name
        raise "Argument must be a OpenSSL::X509::Name"
      end

      WrappedDistinguishedName.new(openssl_name)
    end
  end

  ## This is a significantly more complicated case. It's possible that
  ## generically handled certificates will include custom OIDs in the
  ## subject.
  class WrappedDistinguishedName < DistinguishedName
    attr_accessor :x509_name

    def initialize(x509_name)
      @x509_name = x509_name

      subject = @x509_name.to_a
      subject.each do |element|
        field = element[0].downcase
        value = element[1]
        #type = element[2] ## -not used
        method_sym = "#{field}=".to_sym
        if self.respond_to?(method_sym)
          self.send("#{field}=",value)
        else
          ## Custom OID
          @custom_oids = true
        end
      end

    end

    def to_x509_name
      @x509_name
    end

    def custom_oids?
      @custom_oids
    end
  end
end
