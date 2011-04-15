module CertificateAuthority
  class SerialNumber
    include ActiveModel::Validations
    
    attr_accessor :number
    
    validates :number, :presence => true
    # validate do |serial|
    #   errors.add :serial, "Must have a serial number" if serial.number.nil?
    # end
    
  end
end