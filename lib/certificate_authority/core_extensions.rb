#
# ActiveSupport has these modifications. Now that we don't use ActiveSupport,
# these are added here as a kindness.
#

unless nil.respond_to?(:blank?)
  class NilClass
    def blank?
      true
    end
  end
end

unless String.respond_to?(:blank?)
  class String
    def blank?
      self.empty?
    end
  end
end
