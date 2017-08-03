#!/usr/bin/ruby
require 'time'
require 'date'
require 'fileutils'
require 'net/http'
require 'uri'

### define class
class String
def red;            "\033[31m#{self}\033[0m" end
def green;          "\033[32m#{self}\033[0m" end
def yellow;           "\033[33m#{self}\033[0m" end
def bold;           "\033[1m#{self}\033[22m" end
def bg_grey;        "\033[47m#{self}\033[0m" end
end

class Sslinfo
  attr_accessor :subject, :issuer, :startdate, :enddate, :file, :modulus, :intermediatecert, :serverca, :clientca, :subject_alt, :hpkp
  def initialize(subject, issuer, subject_alt, startdate, enddate, serverca, clientca, file, modulus, intermediatecert, hpkp)
  @subject = subject
  @file = file
  @subject_alt = subject_alt
  @issuer = issuer
  @startdate = startdate
  @enddate = enddate
  @serverca = serverca
  @clientca = clientca
  @modulus = modulus
  @intermediatecert = intermediatecert
  @hpkp = hpkp
  end

  def to_ary
    [subject, issuer, enddate, file]
  end
end

if !system("which openssl > /dev/null 2>&1")
 abort "ERROR: openssl does not seem to be available".red
end

if ARGV[0]
 if File.directory?("#{ARGV[0]}")
 CURWD = Dir.pwd
 Dir.chdir(ARGV[0])
	if ARGV[1]
	OUTPUTDIR = ARGV[1]
	else
 	OUTPUTDIR = Dir.pwd 
	end
 Dir.chdir(CURWD)
 else
 abort "ERROR: outputdir #{ARGV[0]} does not exist".red
 end
else
 abort "ERROR: please use: #{$0}: [outputdir, should exist] [absolute-path-to-files (optional, will be absolute to outputdir if not specified)]".red
end


CAFILE="#{File.dirname("#{$0}")}/curl-ca-bundle.crt"
TIMES = Hash.new
TIMES["now"] =Time.now.to_i
TIMES["90day"] = Time.parse("#{Date.today + 90}".to_s).to_i
TIMES["180day"] = Time.parse("#{Date.today + 180}".to_s).to_i
CAINFO = %x[openssl  crl2pkcs7 -nocrl -certfile #{CAFILE}| openssl pkcs7 -print_certs ]

moduluskeyinfo=Hash.new
moduluscertinfo=Hash.new
processedinfo=Hash.new


#### define defs

def parse_key_file(file)
encrypt = %x[grep ENCRYPTED #{file}].length
 if encrypt < 1
  modulus=%x[cat #{file} | openssl rsa -noout -modulus]
  return "#{modulus.split('=')[1].strip}"
 else
  puts "skipping keyfile #{file} as it is encrypted".yellow.bold
 end
end

def parse_cert_file(file)
modulus=%x[cat #{file} | openssl x509 -noout -modulus]
return "#{modulus.split('=')[1].strip}"
end

def sslparser(processedinfo,type,parsedinfo,subject_alt='NA',file='NA', modulus='NA', intermediatecert='NA', hpkp='')
 enddate='NA'
 enddate_i='NA'
 startdate='NA'
 startdate_i='NA'
 subject='NA'
 issuer='NA'
 serverca='NA'
 clientca='NA'
 parsedinfo.each_line {|line|
 serverca=line.split(' : ')[1].strip if line =~ /SSL server CA/
 clientca=line.split(' : ')[1].strip if line =~ /SSL client CA/
   if line =~ /^notAfter=.*$/
        enddate = line.split('notAfter=')[1].strip
        enddate_i = Time.parse(enddate).to_i
   end
   if line =~ /^notBefore=.*$/
        startdate = line.split('notBefore=')[1].strip
        startdate_i = Time.parse(startdate).to_i
   end
   if line =~ /^subject=.*$/
        subject = line.split('subject= ')[1].strip
   end
   if line =~ /^issuer=.*$/
        issuer = line.split('issuer= ')[1].strip
   end
}
   case type
	when /CA|INT/
   	return Sslinfo.new(subject, issuer, '', startdate_i, enddate_i, serverca, clientca, file, modulus, intermediatecert, hpkp)
	when /CLIENT/
   	return Sslinfo.new(subject, issuer, subject_alt, startdate_i, enddate_i, serverca, clientca, file, modulus, intermediatecert, hpkp)
   end
end


def magic_generate(hash,cn)
begin
startdate=DateTime.strptime("#{hash["startdate"]}",'%s').strftime("%Y_%m_%d")
enddate=DateTime.strptime("#{hash["enddate"]}",'%s').strftime("%Y_%m_%d")
keyfiletobe="#{OUTPUTDIR}/#{cn}/#{cn}__#{startdate}_#{enddate}.keyfile"
certfiletobe="#{OUTPUTDIR}/#{cn}/#{cn}__#{startdate}_#{enddate}.certificate.pem"
FileUtils.mkdir "#{OUTPUTDIR}/#{cn}" if ! File.directory?("#{OUTPUTDIR}/#{cn}")
FileUtils.cp(hash["keyfile"],"#{keyfiletobe}")
FileUtils.cp(hash["file"],"#{certfiletobe}")
## rewrite the cert to add some debuginfo
certfile=File.open("#{certfiletobe}",'r')
certfiledata=certfile.read
certfile.close
certfile=File.open("#{certfiletobe}",'w')
marker="cert: #{cn} alt: #{hash["subject_alt"]} originalfile: #{hash["file"]}"
certfile.write("#{marker}\n#{marker.gsub(/./, '=')}\n#{certfiledata}")
certfile.close
## intermediate data
 if hash["intermediatecert"]
 intermediate=Net::HTTP.get(URI.parse(hash["intermediatecert"]))
 intermediate_base=File.basename("#{hash["intermediatecert"]}")
 ## write intermediate cert
 File.open("#{OUTPUTDIR}/#{cn}/#{intermediate_base}", 'w') { |file| file.write(intermediate) }
 #File.open("#{OUTPUTDIR}/#{cn}/#{intermediate_base}", 'w') { |file| file.write("#{intermediate_base}\n================\n") ; file.write(intermediate) }
 ## convert to pem
 %x[openssl x509 -inform der -in "#{OUTPUTDIR}/#{cn}/#{intermediate_base}" -out "#{OUTPUTDIR}/#{cn}/#{intermediate_base}.pem"]
 FileUtils.rm "#{OUTPUTDIR}/#{cn}/#{intermediate_base}"
 intermediatefile=File.open("#{OUTPUTDIR}/#{cn}/#{intermediate_base}.pem",'r')
 intermediate=intermediatefile.read
 intermediatefile.close
 intermediatefile=File.open("#{OUTPUTDIR}/#{cn}/#{intermediate_base}.pem",'w')
 marker="Intermediate cert: #{intermediate_base} #{hash["intermediatecert"]}"
 intermediatefile.write("#{marker}\n#{marker.gsub(/./, '=')}\n#{intermediate}")
 intermediatefile.close
 
 ## do we need to fetch one more intermediate?
 check_for_more_certs="#{OUTPUTDIR}/#{cn}/#{intermediate_base}.pem"
  checkurl=''
  checkcaissuer=%x[openssl x509 -text -certopt no_subject,no_header,no_version,no_serial,no_pubkey,no_sigdump,no_aux   -noout -in "#{check_for_more_certs}"]
  checkcaissuer.each_line {|line|
  checkurl=line.split('CA Issuers -')[1].gsub('URI:','').strip if line =~ /^.*CA Issuers.*$/
  }

  if checkurl.length > 0
   intermediate_extra=Net::HTTP.get(URI.parse(checkurl))
   intermediate_base_extra=File.basename("#{checkurl}")
   File.open("#{OUTPUTDIR}/#{cn}/#{intermediate_base}_#{intermediate_base_extra}", 'w') { |file| file.write(intermediate_extra) }
   %x[openssl x509 -inform der -in "#{OUTPUTDIR}/#{cn}/#{intermediate_base}_#{intermediate_base_extra}" -out "#{OUTPUTDIR}/#{cn}/#{intermediate_base}_#{intermediate_base_extra}.pem"]
   FileUtils.rm "#{OUTPUTDIR}/#{cn}/#{intermediate_base}_#{intermediate_base_extra}"
   addtofile=File.open("#{OUTPUTDIR}/#{cn}/#{intermediate_base}_#{intermediate_base_extra}.pem",'r')
   addtofile_data=addtofile.read
   addtofile.close
   currentfile=File.open("#{OUTPUTDIR}/#{cn}/#{intermediate_base}.pem",'a')
   marker="Intermediate cert: #{intermediate_base_extra} #{checkurl}"
   currentfile.write("#{marker}\n#{marker.gsub(/./, '=')}\n#{addtofile_data}")
   currentfile.close
   FileUtils.rm "#{OUTPUTDIR}/#{cn}/#{intermediate_base}_#{intermediate_base_extra}.pem"
  end

 opensslverify=%x[openssl verify -CAfile "#{CAFILE}" -untrusted "#{OUTPUTDIR}/#{cn}/#{intermediate_base}.pem" "#{certfiletobe}"].strip
 else
 opensslverify=%x[openssl verify -CAfile "#{CAFILE}" "#{certfiletobe}"].strip
 end

if opensslverify =~ /^.*OK$/
 puts "generate #{cn} #{startdate} #{enddate} -> #{opensslverify}".green
else
 puts "generate #{cn} #{startdate} #{enddate} -> #{opensslverify}".yellow
end 

## nginx config (merge cert + intermediates to one file)
 certfile=File.open("#{certfiletobe}",'r')
 certdata=certfile.read
 certfile.close
 certintermediatesfile=File.open("#{OUTPUTDIR}/#{cn}/#{intermediate_base}.pem",'r')
 certintermediatesfiledata=certintermediatesfile.read
 certintermediatesfile.close
 hpkpintermediatesfile="pin-sha256=\"#{%x[openssl x509 -in "#{OUTPUTDIR}/#{cn}/#{intermediate_base}.pem" -pubkey -noout | openssl rsa -pubin -outform der 2>/dev/null | openssl dgst -sha256 -binary | openssl enc -base64].strip}\"; "

 nginxcertfile=File.open("#{OUTPUTDIR}/#{cn}/#{cn}.nginx.certificates",'w')
 nginxcertfile.write("#{certdata}\n#{certintermediatesfiledata}\n")
 nginxcertfile.close

 configfile=File.open("#{OUTPUTDIR}/#{cn}.nginx.conf",'w')
 if certintermediatesfiledata.length > 1
 hpkpheaders="#{hash["hpkp"]} #{hpkpintermediatesfile}" 
 else
 hpkpheaders="#{hash["hpkp"]}"
 end
 extra_header="\nadd_header Public-Key-Pins '#{hpkpheaders} max-age=2592000;'\n\n"
 configfile.write("ssl_certificate #{OUTPUTDIR}/#{cn}/#{cn}.nginx.certificates;\nssl_certificate_key #{keyfiletobe}\n")
 configfile.close

## apache config
 configfile=File.open("#{OUTPUTDIR}/#{cn}.apache.conf",'w')
 configfile.write("SSLCertificateFile #{certfiletobe}\nSSLCertificateKeyFile #{keyfiletobe}\nSSLCACertificateFile #{intermediate_base}.pem\n")
 configfile.close
end
end


### main parsing


## parse all CA info
started=0
subject=''
issuer=''
sslinfo=''
CAINFO.each_line {|line|
subject = line.split('subject=')[1].strip if line =~ /^subject.*$/
issuer = line.split('issuer=')[1].strip if line =~ /^issuer.*$/
started=1 if line =~ /^.*BEGIN CERTIFICATE.*$/
if started == 1
 then
 sslinfo+=line
end

if line =~ /^.*END CERTIFICATE.*$/
 parsedinfo=%x[echo "#{sslinfo}" | openssl x509 -purpose -enddate -startdate -subject -issuer  -noout ]
 #hpkp="pin-sha256=\"#{%x[echo "#{sslinfo}" | openssl x509 -pubkey -noout | openssl rsa -pubin -outform der 2>/dev/null | openssl dgst -sha256 -binary | openssl enc -base64].strip}\"; "
 started=0
 sslinfo=''
 processedinfo["#{subject}"] = sslparser(processedinfo,'CA',parsedinfo)
 #processedinfo["#{subject}"] = sslparser(processedinfo,'CA',parsedinfo,'','','','',hpkp)
 break
end
}
## end CA parsing


## Parse all normal certs
started=0
subject=''
issuer=''
sslinfo=''
certsdirs = Dir.glob('*').select {|f| File.directory? f }.push(".")
certsdirs.each {|dir|
 certsfiles = Dir["#{dir}/*"]
 certsfiles.each {|file|
 mime = %x[file #{file}]
 case mime
	when /^.*key$/
	moduluskeyinfo["#{parse_key_file(file)}"] = "#{file}"
	when /^.*certificate$/
	modulus=parse_cert_file(file)
	moduluscertinfo["#{modulus}"] = "#{file}"
        parsedinfo=%x[openssl x509 -purpose -enddate -startdate -subject -issuer  -noout -in "#{file}"]
	parsedinfov2=%x[openssl x509 -text -certopt no_subject,no_header,no_version,no_serial,no_pubkey,no_sigdump,no_aux   -noout -in "#{file}"]
	subject_alternatives=''
	intermediatecert=''
	parsedinfov2.each_line {|linev2| 	subject_alternatives=linev2.strip.gsub('DNS:','') if linev2 =~ /^.*DNS.*$/ 	;intermediatecert=linev2.split('CA Issuers -')[1].gsub('URI:','').strip if linev2 =~ /^.*CA Issuers.*$/}
	hpkp="pin-sha256=\"#{%x[openssl x509 -in '#{file}' -pubkey -noout | openssl rsa -pubin -outform der 2>/dev/null | openssl dgst -sha256 -binary | openssl enc -base64].strip}\"; "
	processedinfo["#{file}"] = sslparser(processedinfo,'CLIENT',parsedinfo,subject_alternatives,file,modulus,intermediatecert,hpkp)
	end
	}
}


tmphash=Hash.new

processedinfo.keys.each {|subject|
## enduser cert check
if processedinfo["#{subject}"].serverca == 'No'

 certcn=processedinfo["#{subject}"].subject.split('CN=')[1].strip
 tmpmodulus=processedinfo["#{subject}"].modulus
 human_startdate=DateTime.strptime("#{processedinfo["#{subject}"].startdate}",'%s').strftime("%Y_%m_%d")
 human_enddate=DateTime.strptime("#{processedinfo["#{subject}"].enddate}",'%s').strftime("%Y_%m_%d")

 if processedinfo["#{subject}"].startdate > TIMES["now"]
 puts "cert #{subject} not allowed to be used yet (#{processedinfo["#{subject}"].file} start:#{human_startdate} end:#{human_enddate})"
 end

 if processedinfo["#{subject}"].enddate < TIMES["now"]
 puts "cert #{subject} expired (start:#{human_startdate} end:#{human_enddate})".red.bold.bg_grey
 next
 elsif processedinfo["#{subject}"].enddate < TIMES["90day"]
 puts "cert #{subject} expiring within 90 days (start:#{human_startdate} end:#{human_enddate})".yellow
 elsif processedinfo["#{subject}"].enddate <= TIMES["180day"] and processedinfo["#{subject}"].enddate >= TIMES["90day"]
 puts "cert #{subject} expiring within 180 days (start:#{human_startdate} end:#{human_enddate})".green
 end


 if !tmphash.key?("#{certcn}")
  if moduluskeyinfo.key?("#{tmpmodulus}")
   tmphash["#{certcn}"] = Hash.new
   tmphash["#{certcn}"]['keyfile'] = moduluskeyinfo["#{tmpmodulus}"] 
  else
   puts "ERROR: no known keyfile for cert #{certcn} (#{processedinfo["#{subject}"].file} start:#{human_startdate} end:#{human_enddate})".red
   next
  end
  #puts "creating new hash for #{certcn}"
  tmphash["#{certcn}"]['startdate'] = processedinfo["#{subject}"].startdate
  tmphash["#{certcn}"]['enddate'] = processedinfo["#{subject}"].enddate
  tmphash["#{certcn}"]['file'] = processedinfo["#{subject}"].file
  tmphash["#{certcn}"]['modulus'] = "#{tmpmodulus}"
  tmphash["#{certcn}"]['intermediatecert'] = processedinfo["#{subject}"].intermediatecert
  tmphash["#{certcn}"]['issuer'] = processedinfo["#{subject}"].issuer
  tmphash["#{certcn}"]['subject_alt'] = processedinfo["#{subject}"].subject_alt
  tmphash["#{certcn}"]['hpkp'] = processedinfo["#{subject}"].hpkp
 elsif tmphash["#{certcn}"]['startdate'] <= processedinfo["#{subject}"].startdate
  if moduluskeyinfo.key?("#{tmpmodulus}")
   tmphash["#{certcn}"]['keyfile'] = moduluskeyinfo["#{tmpmodulus}"] 
  else
   puts "ERROR: no known keyfile for cert #{certcn} (#{processedinfo["#{subject}"].file} start:#{human_startdate} end:#{human_enddate})".red
   next
  end
  tmphash_human_startdate=DateTime.strptime("#{tmphash["#{certcn}"]['startdate']}",'%s').strftime("%Y_%m_%d")
  tmphash_human_enddate=DateTime.strptime("#{tmphash["#{certcn}"]['enddate']}",'%s').strftime("%Y_%m_%d")
  puts "updating hash for #{certcn} (old: #{tmphash["#{certcn}"]['file']} #{tmphash_human_startdate}/#{tmphash_human_enddate}, new: #{processedinfo["#{subject}"].file} start:#{human_startdate} end:#{human_enddate}".green
  tmphash["#{certcn}"]['startdate'] = processedinfo["#{subject}"].startdate
  tmphash["#{certcn}"]['enddate'] = processedinfo["#{subject}"].enddate
  tmphash["#{certcn}"]['file'] = processedinfo["#{subject}"].file
  tmphash["#{certcn}"]['modulus'] = "#{tmpmodulus}"
  tmphash["#{certcn}"]['intermediatecert'] = processedinfo["#{subject}"].intermediatecert
  tmphash["#{certcn}"]['issuer'] = processedinfo["#{subject}"].issuer
  tmphash["#{certcn}"]['subject_alt'] = processedinfo["#{subject}"].subject_alt
  tmphash["#{certcn}"]['hpkp'] = processedinfo["#{subject}"].hpkp
 else
  tmphash_human_startdate=DateTime.strptime("#{tmphash["#{certcn}"]['startdate']}",'%s').strftime("%Y_%m_%d")
  puts "skipping CN:#{certcn} #{subject} #{human_startdate} is issued before #{tmphash_human_startdate}, so keeping #{tmphash["#{certcn}"]['file']}".yellow
 end

end

}

tmphash.keys.each {|cn|
magic_generate(tmphash["#{cn}"],"#{cn}")
}


exit
