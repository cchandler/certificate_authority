module CertificateAuthority
  class DistinguishedName
    include ActiveModel::Validations
    
    validates_presence_of :common_name
    
    attr_accessor :common_name
    alias :cn :common_name
    
    attr_accessor :locality
    alias :l :locality
    
    attr_accessor :state
    alias :s :state
    
    attr_accessor :country
    alias :c :country
    
    attr_accessor :organization
    alias :o :organization
    
    attr_accessor :organizational_unit
    alias :ou :organizational_unit
    
    def to_x509_name
      raise "Invalid Distinguished Name" unless valid?
      
      # NB: the capitalization in the strings counts
      name = OpenSSL::X509::Name.new
      name.add_entry("CN", common_name)
      name.add_entry("O", organization) unless organization.blank?
      name.add_entry("OU", organizational_unit) unless organizational_unit.blank?
      name.add_entry("ST", state) unless state.blank?
      name.add_entry("L", locality) unless locality.blank?
      name.add_entry("C", country) unless country.blank?
      name
    end
  end
end