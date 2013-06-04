module CertificateAuthority
  class SerialNumber
    include ActiveModel::Validations
    include Revocable

    attr_accessor :number

    validates :number, :presence => true, :numericality => {:greater_than => 0}

    def initialize
      self.number = SecureRandom.random_number(2**128-1)
    end
  end
end
