module CertificateAuthority
  module Revocable
    attr_accessor :revoked_at

    def revoke!(time=Time.now)
      @revoked_at = time
    end

    def revoked?
      # If we have a time, then we're revoked
      !@revoked_at.nil?
    end
  end
end
