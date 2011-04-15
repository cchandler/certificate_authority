require 'certificate_authority'

namespace :certificate_authority do
  desc "Generate a quick self-signed cert"
  task :self_signed do
    
    cn = "http://localhost"
    cn = ENV['DOMAIN'] unless ENV['DOMAIN'].nil?
    
  	root = CertificateAuthority::Certificate.new
  	root.subject.common_name= cn
  	root.key_material.generate_key
  	root.signing_entity = true
  	root.valid?
  	root.sign!
  	
  	print "Your cert for #{cn}\n"
  	print root.to_pem
  	
  	print "Your private key\n"
  	print root.key_material.private_key.to_pem
  end
end
