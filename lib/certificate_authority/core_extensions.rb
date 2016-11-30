#
# ActiveSupport has these modifications. Now that we don't use ActiveSupport,
# these are added here as a kindness.
#

require 'date'

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

class Date

  def today
    t = Time.now.utc
    Date.new(t.year, t.month, t.day)
  end

  def utc
    self.to_datetime.to_time.utc
  end

  unless Date.respond_to?(:advance)
    def advance(options)
      options = options.dup
      d = self
      d = d >> options.delete(:years) * 12 if options[:years]
      d = d >> options.delete(:months)     if options[:months]
      d = d +  options.delete(:weeks) * 7  if options[:weeks]
      d = d +  options.delete(:days)       if options[:days]
      d
    end
  end
end
