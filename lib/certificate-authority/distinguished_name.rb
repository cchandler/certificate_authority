module CertificateAuthority
  class DistinguishedName
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
  end
end