# certificate-organiser

features
- auto-discovery of matching key/cert pairs (note, does not work on encrypted files)
- structuring the key/cert pairs to a standardized naming scheme
- easy-includes for nginx/apache
- auto-fetching of intermediate cert-data

usage:
imagine you have a dir full of unsorted certs and keys in
/usr/share/local/messy-certs

and you want these organized on cert CN name, start&end date, intermediates added and tested with openssl verify
then you would now be able to..

1) checkout this repo
   git clone https://github.com/dmclf/certificate-organiser.git
2) cd /usr/share/local/messy-certs
   ~/certificate-organiser/certificate-organiser.rb /usr/share/local/clean-certs

then in /usr/share/local/clean-certs
you would get the certs as
/usr/share/local/clean-certs/mydomain

/usr/share/local/clean-certs/my.exampledomain.org.apache.conf
/usr/share/local/clean-certs/my.exampledomain.org.nginx.conf
/usr/share/local/clean-certs/my.exampledomain.org/my.exampledomain.org.nginx.certificates
/usr/share/local/clean-certs/my.exampledomain.org/my.exampledomain.org__2016_11_21_2017_11_22.keyfile
//usr/share/local/clean-certs/my.exampledomain.org/my.exampledomain.org__2016_11_21_2017_11_22.certificate.pem
/usr/share/local/clean-certs/my.exampledomain.org/COMODORSADomainValidationSecureServerCA.crt.pem

where the /usr/share/local/clean-certs/my.exampledomain.org.nginx.conf you can use ready to use as 
include /usr/share/local/clean-certs/my.exampledomain.org.nginx.conf;

and /usr/share/local/clean-certs/my.exampledomain.org.apache.conf for apache

