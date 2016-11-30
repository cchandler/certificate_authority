#
# This is a super simple replacement for ActiveSupport::Validations
#

module CertificateAuthority
  class Errors < Array
    def add(symbol, msg)
      self.push([symbol, msg])
    end
    def full_messages
      self.map {|i| i[0].to_s + ": " + i[1]}.join("\n")
    end
  end

  module Validations
    def valid?
      @errors = Errors.new
      validate
      errors.empty?
    end

    # must be overridden
    def validate
      raise NotImplementedError
    end

    def errors
      @errors ||= Errors.new
    end
  end
end
