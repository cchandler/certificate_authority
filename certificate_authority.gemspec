require File.expand_path("lib/certificate_authority/version", __dir__)

Gem::Specification.new do |spec|
  spec.name = "certificate_authority"
  spec.version = CertificateAuthority::VERSION
  spec.authors = ["Chris Chandler"]
  spec.email = ["squanderingtime@gmail.com"]

  spec.summary  = "Ruby gem for managing the core functions outlined in RFC-3280 for PKI"
  spec.homepage = "https://github.com/cchandler/certificate_authority"
  spec.license  = "MIT"

  spec.metadata["homepage_uri"] = "https://github.com/cchandler/certificate_authority"
  spec.metadata["source_code_uri"] = "https://github.com/cchandler/certificate_authority"

  spec.files = Dir.chdir(__dir__) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(spec/)}) }
  end
  spec.require_paths = ["lib"]

  spec.required_ruby_version = ">= 2.4"

  spec.add_development_dependency "coveralls"
  spec.add_development_dependency "pry"
  spec.add_development_dependency "rake"
  spec.add_development_dependency "rspec"
  spec.add_development_dependency "rubocop"
end
