require 'securerandom'

module CertificateAuthority
  class SerialNumber
    include Validations
    include Revocable

    attr_accessor :number

    def validate
      if self.number.nil?
        errors.add :number, "must not be empty"
      elsif self.number.to_i <= 0
        errors.add :number, "must be greater than zero"
      end
    end

    def initialize
      self.number = SecureRandom.random_number(2**128-1)
    end
  end
end
