= CertificateAuthority - Because it shouldn't be this damned complicated

{<img src="https://travis-ci.org/cchandler/certificate_authority.png?branch=master" alt="Build Status" />}[https://travis-ci.org/cchandler/certificate_authority]
{<img src="https://codeclimate.com/github/cchandler/certificate_authority.png" alt="Code Climate" />}[https://codeclimate.com/github/cchandler/certificate_authority]
{<img src="https://coveralls.io/repos/cchandler/certificate_authority/badge.png?branch=master" alt="Code Coverage" />}[https://coveralls.io/r/cchandler/certificate_authority]

This is meant to provide a (more) programmer-friendly implementation of all the basic functionality contained in RFC-3280 to implement your own certificate authority.

You can generate root certificates, intermediate certificates, and terminal certificates.  You can also generate/manage Certificate Revocation Lists (CRLs) and Online Certificate Status Protocol (OCSP) messages.

Because this library is built using the native Ruby bindings for OpenSSL it also supports PKCS#11 cryptographic hardware for secure maintenance of private key materials.

= So you want to maintain a certificate authority root

Let's suppose hypothetically you want to be able to issue and manage your own certificates. This section is meant to outline the basic functions you'll need(optionally want) to support.  Not everyone is out to be in total compliance with WebTrust[link:http://www.webtrust.org/] or {Mozilla's rules for CA inclusion}[link:https://wiki.mozilla.org/CA:How_to_apply].

The three primary elements to be aware of are:

[Certificate Authority] These are the functions primarily related to the signing, issuance, and revocation of certificates.

[Registration Authority] These are the functions primarily related to registering and requesting certificates and vetting of the entities requesting certification.

[Validation Authority] These are the functions related to verifying the status of certificates out in the wild.  Mostly CRLs and OCSP related functions.

= Establishing a new root in software

Let's look at a complete example for generating a new root certificate. Assuming that you don't have a PKCS#11 hardware token available (lists coming...) we'll have to store this safe.

Generating a self-signed root certificate is fairly easy:

  require 'certificate_authority'
  root = CertificateAuthority::Certificate.new
  root.subject.common_name= "http://mydomain.com"
  root.serial_number.number=1
  root.key_material.generate_key
  root.signing_entity = true
  signing_profile = {"extensions" => {"keyUsage" => {"usage" => ["critical", "keyCertSign"] }} }
  root.sign!(signing_profile)

The required elements for the gem at this time are a common name for the subject and a serial number for the certificate. Since this is our self-signed root we're going to give it the first serial available of 1. Because certificate_authority is not designed to manage the issuance lifecycle you'll be expected to store serial numbers yourself.

Next, after taking care of required fields, we will require key material for the new certificate.  There's a convenience method made available on the key_material object for generating new keys.  The private key will be available in:

  root.key_material.private_key

and the public key:

  root.key_material.public_key

Make sure to save the private key somewhere safe!

Lastly, we declare that the certificate we're about to sign is itself a signing entity so we can continue on and sign other certificates.

== Creating a new intermediate

Maybe you don't want to actually sign certificates with your super-secret root certificate. This is actually how a good number of most public certificate authorities do it. Rather than sign with the primary root, they generate an intermediate root that is then responsible for signing the final certificates.  If you wanted to create an intermediate root certificate you would do something like the following:

  intermediate = CertificateAuthority::Certificate.new
  intermediate.subject.common_name= "My snazzy intermediate!"
  intermediate.serial_number.number=2
  intermediate.key_material.generate_key
  intermediate.signing_entity = true
  intermediate.parent = root
  signing_profile = {"extensions" => {"keyUsage" => {"usage" => ["critical", "keyCertSign"] }} }
  intermediate.sign!(signing_profile)

All we have to do is create another certificate like we did with the root. In this example we gave it the next available serial number, which for us, was 2.  We then generate (and save!) key material for this new entity.  Even the +signing_entity+ is set to true so this certificate can sign other certificates.  The difference here is that the +parent+ field is set to the root. Going forward, whatever entity you want to sign a certificate, you set that entity to be the parent. In this case, our root will be responsible for signing this intermediate when we call +sign!+.

= Creating new certificates (in general)

Now that we have a root certificate (and possibly an intermediate) we can sign end-user certificates.  It is, perhaps unsurprisingly, similar to all the others:

  plain_cert = CertificateAuthority::Certificate.new
  plain_cert.subject.common_name= "http://mydomain.com"
  plain_cert.serial_number.number=4
  plain_cert.key_material.generate_key
  plain_cert.parent = root # or intermediate
  plain_cert.sign!

That's all there is to it!  In this example we generate the key material ourselves, but it's possible for the end-user to generate certificate signing request (CSR) that we can then parse and consume automatically (coming soon).  To get the PEM formatted certificate for the user you would need to call:

  plain_cert.to_pem

to get the certificate body.

= Signing Profiles

Creating basic certificates is all well and good, but maybe you want _more_ signing control.  +certificate_authority+ supports the idea of signing profiles.  These are hashes containing values that +sign!+ will use to merge in additional control options for setting extensions on the certificate.

Here's an example of a full signing profile for most of the common V3 extensions:

   signing_profile = {
     "extensions" => {
       "basicConstraints" => {"ca" => false},
       "crlDistributionPoints" => {"uri" => "http://notme.com/other.crl" },
       "subjectKeyIdentifier" => {},
       "authorityKeyIdentifier" => {},
       "authorityInfoAccess" => {"ocsp" => ["http://youFillThisOut/ocsp/"] },
       "keyUsage" => {"usage" => ["digitalSignature","nonRepudiation"] },
       "extendedKeyUsage" => {"usage" => [ "serverAuth","clientAuth"]},
       "subjectAltName" => {"uris" => ["http://subdomains.youFillThisOut/"]},
       "certificatePolicies" => {
       "policy_identifier" => "1.3.5.8", "cps_uris" => ["http://my.host.name/", "http://my.your.name/"], 
         "user_notice" => {
          "explicit_text" => "Explicit Text Here", 
         "organization" => "Organization name",
         "notice_numbers" => "1,2,3,4"
         }
       }
     }
  }

Using a signing profile is done this way:

  certificate.sign!(signing_profile)

At that point all the configuration options will be merged into the extensions.

== Basic Constraints

The basic constraints extension allows you to control whether or not a certificate can sign other certificates.

[CA] If this value is true then this certificate has the authority to sign additional certificates.

[pathlen] This is the maximum length of the chain-of-trust.  For instance, if an intermediate certificate has a pathlen of 1 then it can sign additional certificates, but it cannot create another signing entity because the total chain-of-trust would have a length greater than 1.

== CRL Distribution Points

This extension controls where a conformant client can go to obtain a list of certificate revocation information.  At this point +certificate_authority+ only supports a list of URIs.  The formal RFC however provides for the ability to provide a URI and an issuer identifier that allows a different signing entity to generate/sign the CRL.

[uri] The URI in subject alternative name format of the URI endpoint.  Example: "http://ca.chrischandler.name/some_identifier.crl"

== Subject Key Identifier

This extension is required to be present, but doesn't offer any configurable parameters.  Directly from the RFC:

  The subject key identifier extension provides a means of identifying
  certificates that contain a particular public key.

  To facilitate certification path construction, this extension MUST
  appear in all conforming CA certificates, that is, all certificates
  including the basic constraints extension (section 4.2.1.10) where
  the value of cA is TRUE.  The value of the subject key identifier
  MUST be the value placed in the key identifier field of the Authority
  Key Identifier extension (section 4.2.1.1) of certificates issued by
  the subject of this certificate.

== Authority Key Identifier

Just like the subject key identifier, this is required under most circumstances and doesn't contain any meaningful configuration options.  From the RFC:

  The keyIdentifier field of the authorityKeyIdentifier extension MUST
  be included in all certificates generated by conforming CAs to
  facilitate certification path construction.  There is one exception;
  where a CA distributes its public key in the form of a "self-signed"
  certificate, the authority key identifier MAY be omitted.  The
  signature on a self-signed certificate is generated with the private
  key associated with the certificate's subject public key.  (This
  proves that the issuer possesses both the public and private keys.)
  In this case, the subject and authority key identifiers would be
  identical, but only the subject key identifier is needed for
  certification path building.

== Authority Info Access

The authority info access extension allows a CA to sign a certificate with information a client can use to get up-to-the-minute status information on a signed certificate.  This takes the form of an OCSP[link:http://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol] (Online Certificate Status Protocol) endpoints.

[ocsp] This is an array of URIs specifying possible endpoints that will be able to provide a signed response. +certificate_authority+ has an OCSP message handler for parsing OCSP requests and generating OCSP signed responses.

== Key Usage

This extension contains a list of the functions this certificate is allowed to participate in.

[usage] An array of OIDs in string format. The acceptable values are specified by OpenSSL and are: +digitalSignature+, +nonRepudiation+, +keyEncipherment+, +dataEncipherment+, +keyAgreement+, +keyCertSign+, +cRLSign+, +encipherOnly+ and +decipherOnly+.

== Extended Key Usage

This one is like key usage, but allows for certain application specific purposes. It's generally only present in end-user certificates.

[usage] An array of OIDs in string format. The only ones with practical significance at this point are: +serverAuth+, +clientAuth+, and +codeSigning+.

== Subject Alternative Name

If the certificate needs to work for multiple domains then you can specify the others for which it is valid in the subject alternative name field.

[uris] An array of full URIs for other common names this certificate should be valid for. For instance, if you want http://ca.chrischandler.name and http://www.ca.chrischandler.name to share the same cert you would place both in the +uris+ attribute of the subject alternative name.

== Certificate Policies

This is one of the most esoteric of the extensions. This allows a conformant certificate authority to embed signing policy information into the certificate body. Public certificate authorities are required to maintain a Certificate Practice Statement in accordance with {RFC 2527}[link:http://www.ietf.org/rfc/rfc2527.txt].

These CPSs define what vetting criteria and maintenance practices are required to issue, maintain, and revoke a certificate. While it might be overkill for private certificates, if you wanted to make an actual public CA you would need to put together a practice statement and embed it in certificates you issue.

[policy_identifier] This is an arbitrary OID (that you make up!) that uniquely represents the policy you are enforcing for whatever kind of certificate this is meant to be.

[cps_uris] This is an array of URIs where a client or human can go to get information related to your certification practice.

[user_notice] This is a nested field containing explicit human readable text if you want to embed a notice in the certificate body related to certification practices. It contains nested attributes of +explicit_text+ for the notice, +organization+ and +notice_numbers+. Refer to the RFC for specific implications of how these are set, but whether or not browsers implement the correct specified behavior for their presence is another issue.

= Certificate Signing Requests (CSRs)

If you want certificate requestors to be able to request certificates without moving the private key you'll need to generate a CSR and submit it to the certificate authority.

Here's an example of using +certificate_authority+ to generate a CSR.

  csr = CertificateAuthority::SigningRequest.new
  dn = CertificateAuthority::DistinguishedName.new
  dn.common_name = "localhost"
  csr.distinguished_name = dn
  k = CertificateAuthority::MemoryKeyMaterial.new
  k.generate_key(2048)
  csr.key_material = k
  csr.digest = "SHA256"
  csr.to_x509_csr.to_pem

Similarly, reading a CSR in is as simple as providing the PEM formatted version to +SigningRequest.from_x509_csr+.

  csr = CertificateAuthority::SigningRequest.from_x509_csr(@pem_csr)

Once you have the CSR in the form of a +SigningRequest+ you can transform it to a +Certificate+ with +to_cert+. At this point it works just like any other certificate. You'll have to provide a serial number to actually sign it.

= Certificate Revocation Lists (CRLs)

Revocation lists let clients know when a certificate in the wild should no longer be trusted.

Like end-user certificates, CRLs have to be signed by a signing authority to be valid. Additionally, you will need to furnish a +nextUpdate+ value that indicates to the client when it should look for updates to the CRL and how long it should consider a cached value valid.

Ideally you would place the result CRL somewhere generally accessible on the Internet and reference the URI in the +crlDistributionPoints+ extension on issued certificates.

  crl = CertificateAuthority::CertificateRevocationList.new
  crl << certificate # Some CertificateAuthority::Certificate
  crl << serial_number # Also works with plain CertificateAuthority::SerialNumber
  crl.parent = root_certificate # A valid root
  crl.next_update = (60 * 60 * 10) # 10 Hours
  crl.sign!
  crl.to_pem

= OCSP Support

OCSP is the Online Certificate Status Protocol. It provides a mechanism to query an authority to see if a certificate is still valid without downloading an entire CRL. To use this mechanism you provide a URI in the Authority Information Access extension.
If a client wishes to check the validity of a certificate they can query this endpoint.
This request will only contain serial numbers, so you'll need to uniquely identify your authority in the AIA path.

If a client sends you a DER encoded OCSP request you can read it out via +OCSPRequestReader+

  ocsp_request_reader = CertificateAuthority::OCSPRequestReader.from_der(@ocsp_request.to_der)
  ocsp_request_reader.serial_numbers

Then, you can construct a response like this

  response_builder = CertificateAuthority::OCSPResponseBuilder.from_request_reader(ocsp_request_reader)
  response_builder.parent = root
  response = response_builder.build_response # Returns OpenSSL::OCSP::Response
  response.to_der

The response builder will copy a (possible) nonce from the request. By default, the +OCSPResponseBuilder+ will say that every certificate is GOOD.
You should definitely override this if you plan on revoking certificates.
If you want to override this you'll need to supply a proc/lambda that takes a serial number and returns an array of status and reason.

  response_builder = CertificateAuthority::OCSPResponseBuilder.from_request_reader(ocsp_request_reader)
  response_builder.verification_mechanism = lambda {|certid|
    [CertificateAuthority::OCSPResponseBuilder::REVOKED,CertificateAuthority::OCSPResponseBuilder::UNSPECIFIED]
  }
  response_builder.parent = root
  response = response_builder.build_response # Response will say everything is revoked for unspecified reasons

Lastly, you can configure a nextUpdate time in the response. This is the length of time for which a client may consider this response valid.
The default is 15 minutes.

  response_builder.next_update = 30 * 60 # 30 minutes

= PKCS#11 Support

If you happen to have a PKCS#11 compliant hardware token you can use +certificate_authority+ to maintain private key materials in hardware security modules. At this point the scope of operating that hardware is out of scope of this README but it's there and it is supported.

To configure a certificate to utilize PKCS#11 instead of in memory keys all you need to do is:

  root = CertificateAuthority::Certificate.new
  root.subject.common_name= "http://mydomain.com"
  root.serial_number.number=1
  root.signing_entity = true

  key_material_in_hardware = CertificateAuthority::Pkcs11KeyMaterial.new
  key_material_in_hardware.token_id = "46"
  key_material_in_hardware.pkcs11_lib = "/usr/lib/libeTPkcs11.so"
  key_material_in_hardware.openssl_pkcs11_engine_lib = "/usr/lib/engines/engine_pkcs11.so"
  key_material_in_hardware.pin = "11111111"

  root.key_material = key_material_in_hardware
  root.sign!

Your current version of OpenSSL _must_ include dynamic engine support and you will need to have OpenSSL PKCS#11 engine support.  You will also require the actual PKCS#11 driver from the hardware manufacturer.  As of today the only tokens I've gotten to work are:

[eTokenPro] Released by Aladdin (now SafeNet Inc.). I have only had success with the version 4 and 5 (32 bit only) copy of the driver. The newer authentication client released by SafeNet appears to be completely broken for interacting with the tokens outside of SafeNet's own tools. If anyone has a different experience I'd like to hear from you.

[ACS CryptoMate] Also a 32-bit only driver. You'll have to jump through some hoops to get the Linux PKCS#11 driver but it works surprisingly well. It also appears to support symmetric key operations in hardware.

[Your company] Do you make a PKCS#11 device? I'd love to get it working but I probably can't afford your device. Get in touch with me and if you're willing to loan me one for a week I can get it listed.

Also of note, I have gotten these to work with 32-bit copies of Ubuntu 10.10 and pre-Snow Leopard versions of OS X. If you are running Snow Leopard you're out of luck since none of the companies I've contacted make a 64 bit driver.

= Hopefully in the future

* More PKCS#11 hardware (I need driver support from the manufacturers)

= Todone

* Support for working with CSRs to request & issue certificates
* OCSP support

= Misc notes

* Firefox will complain about root/intermediate certificates unless both digitalSignature and keyEncipherment are specified as keyUsage attributes. Thanks diogomonica

= Special thanks and Contributions

* Diogo Monica @diogo
* Justin Cummins @sul3n3t
* @databus23
* Colin Jones @trptcolin
* Eric Monti @emonti
* TJ Vanderpoel @bougyman

== Meta

Written by Chris Chandler(http://chrischandler.name)

Released under the MIT License: http://www.opensource.org/licenses/mit-license.php

Main page: http://github.com/cchandler/certificate_authority

Issue tracking: https://github.com/cchandler/certificate_authority/issues
