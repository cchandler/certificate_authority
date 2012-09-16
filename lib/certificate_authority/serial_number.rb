module CertificateAuthority
  class SerialNumber
    include ActiveModel::Validations
    include Revocable

    attr_accessor :number

    validates :number, :presence => true, :numericality => {:greater_than => 0}
  end
end
