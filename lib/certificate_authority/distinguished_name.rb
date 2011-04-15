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
      name.add_entry("OU", common_name) unless organizational_unit.blank?
      name.add_entry("S", common_name) unless state.blank?
      name.add_entry("L", common_name) unless locality.blank?
      
      name
    end
  end
end