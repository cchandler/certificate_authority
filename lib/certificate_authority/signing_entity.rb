module CertificateAuthority
  module SigningEntity
    
    def self.included(mod)
      mod.class_eval do
        attr_accessor :signing_entity 
      end
    end
    
    def signing_entity=(val)
      throw "invalid param" unless [true,false].include?(val)
      @signing_entity = val
    end
    
    def is_signing_entity?
      (is_root_entity? or is_intermediate_entity?) and @signing_entity
    end
    
    def is_root_entity?
      self.parent == self
    end
    
    def is_intermediate_entity?
      (self.parent != self) and @signing_entity
    end
    
  end
end