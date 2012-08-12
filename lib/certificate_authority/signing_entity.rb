module CertificateAuthority
  module SigningEntity

    def self.included(mod)
      mod.class_eval do
        attr_accessor :signing_entity
      end
    end

    def signing_entity=(val)
      raise "invalid param" unless [true,false].include?(val)
      @signing_entity = val
    end

  end
end
