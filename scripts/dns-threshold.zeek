# how many times do you do that in a given duration (say 5 mins ) ?

# total number of lookups per IP per day
# acceleration/spike: fastest/quickest threshold reacher

# 1. count all the lookups per IP for 1 min
# 2.  check if the threshold for above IP is reached - cache the threshold counter for 1 mins
# 3. if threshold is hit, increment rate counter by 1
# 4. expire counters and data from tables after 1 min
# 5. check if rate_counter > rolling_threshold
#	if yes - fire alert
# 6. Repeat 1, 2, 3, 4
# 7. check if rate_counter has expired, set to zero
# loop

module DNS;

export {
	redef enum Notice::Type += {
		Threshold,
		Spike,
	};

	const dns_threshold: vector of count = {
		100000,
		200000,
		300000,
		400000,
		500000,
		800000,
		1000000,
	} &redef;

	const dns_spike_counters: vector of count = {
		100,
	} &redef;

	const Spike_Threshold = 400 &redef;
	const Spike_Rolling_Threshold = 3 &redef;

	type DNS_SpikeThresholdRecord: record {
		first_seen_time: time &optional;
		cur_time: time &optional;
		tally: count &log &default=0;
	};

	global flush_dns_spike_ip_counter: function(t: table[addr] of
	    DNS_SpikeThresholdRecord, orig: addr): interval;

	global dns_spike_ip_counter: table[addr] of DNS_SpikeThresholdRecord
	    &create_expire=1 sec &expire_func=flush_dns_spike_ip_counter &redef;

	global dns_spike_idx: table[addr] of count &default=0 &create_expire=100 msec &redef;

	global dns_spike_idx_2: table[addr] of count &default=0 &create_expire=3 min &redef;

	global dns_servers: set[addr] &redef;

	redef DNS::dns_servers += {
		8.8.8.8,
		8.8.4.4,
		[2001:4860:4860::8888],
		[2001:4860:4860::8844],
	};

	global ok_threshold: set[addr] &redef;

	# we don't want to ignore the counts, but only ignore the emails
	#redef DNS::dns_servers += ignore_thresholds ;

	global dns_ip_thresholds: table[addr] of count &create_expire=1 days &redef;

	global dns_ip_threshold_idx: table[addr] of count &default=0 &write_expire=1 day &redef;

	const ok_dns_spike_host: set[addr] &redef;
}

#hook Notice::policy (n: Notice::Info) {
#   if ( n$note == DNS::Threshold && n$src !in DNS::ok_threshold)
#		{ add n$actions[Notice::ACTION_EMAIL];}
#   if (n$note == DNS::Spike && n$src !in DNS::ok_dns_spike_host)
#		{ add n$actions[Notice::ACTION_EMAIL];}
#  }

#event print_tables(ip: table[addr] of DNS_SpikeThresholdRecord, idx: table[addr] of count,
#    idx2: table[addr] of count)
#{ #print fmt ("%s", ip);
#  #print fmt ("%s", idx);
#  #print fmt ("%s", idx2);
#}

event zeek_init() &priority=5
{ # 	schedule 2 sec {print_tables(dns_spike_ip_counter, dns_spike_idx, dns_spike_idx_2)};
    }

function flush_dns_spike_ip_counter(t: table[addr] of DNS_SpikeThresholdRecord,
    orig: addr): interval
{
	#print fmt ("fired the expirefunction %s %d", orig , |t[orig]$tally|);

	delete t[orig];

	return 0 sec;
}

function check_ip_threshold(v: vector of count, idx: table[addr] of count,
    orig: addr, n: count): bool
{
	#print fmt ("orig: %s and IDX_orig: %s and n is: %s and v[idx[orig]] is: %s", orig, idx[orig], n, v[idx[orig]]);
	if ( idx[orig] < |v| && n >= v[idx[orig]] ) {
		++idx[orig];

		return ( T );
	} else
		return ( F );
}

event DNS::log_dns(rec: DNS::Info)
{
	local request_ip: addr;
	local check_thresh: bool;
	local msg = "";

	request_ip = rec$id$orig_h;

	if ( rec?$query && request_ip !in dns_servers ) {
		local thresh_rec: DNS_SpikeThresholdRecord;

		if ( request_ip !in dns_spike_ip_counter ) {
			thresh_rec$tally = 1;
			thresh_rec$first_seen_time = rec$ts;
			thresh_rec$cur_time = rec$ts;
			dns_spike_ip_counter[request_ip] = thresh_rec;
		}
		thresh_rec$tally = dns_spike_ip_counter[request_ip]$tally + 1;
		thresh_rec$cur_time = rec$ts;
		thresh_rec$first_seen_time = dns_spike_ip_counter[request_ip]$first_seen_time;
		dns_spike_ip_counter[request_ip] = thresh_rec;

		local n = |dns_spike_ip_counter[request_ip]$tally|;

		#i   print fmt ("IP [%s]: tally: %d", request_ip, n);

		if ( ( dns_spike_ip_counter[request_ip]$cur_time -
		    dns_spike_ip_counter[request_ip]$first_seen_time ) <= 1 sec ) {
			n = |dns_spike_ip_counter[request_ip]$tally|;

			if ( n >= Spike_Threshold ) {
				#				print fmt ("IP: [%s] ==>  %s", request_ip, dns_spike_ip_counter[request_ip]);

				msg = fmt("IP[%s] has done %s (First:%s, cur: %s, diff: %s) look ups: %d",
				    request_ip,
				    dns_spike_ip_counter[request_ip]$tally, dns_spike_ip_counter[request_ip]$first_seen_time,
				    dns_spike_ip_counter[request_ip]$cur_time,
				    dns_spike_ip_counter[request_ip]$cur_time - dns_spike_ip_counter[request_ip]$first_seen_time, n);
				#local msg = fmt ("ip_counter[%s]:  %s", request_ip, dns_spike_ip_counter[request_ip]$tally);
				local time_diff: interval;

				if ( request_ip !in dns_spike_idx_2 )
					dns_spike_idx_2[request_ip] = 0;

				dns_spike_idx_2[request_ip] += 1;

				time_diff = dns_spike_ip_counter[request_ip]$cur_time - dns_spike_ip_counter[request_ip]$first_seen_time;
				delete dns_spike_ip_counter[request_ip];

				#print fmt ("INSIDE: dns_spike_idx_2[%s] %s is %d",request_ip, dns_spike_idx_2[request_ip],|dns_spike_idx_2[request_ip]|);

				if ( |dns_spike_idx_2[request_ip]| >= DNS::Spike_Rolling_Threshold ) {
					if ( time_diff < 60 sec ) {
						NOTICE([
						    $note=DNS::Spike,
						    $src=request_ip,
						    $msg=msg,
						    $identifier=cat(request_ip)]);
					#print fmt ("Consistant threshold reached for %s : %s in %s", request_ip, |dns_spike_idx_2[request_ip]|, time_diff );
					}
				}
			} # n > spike_threshold
		} # <= 1 sec
		    else {
			delete dns_spike_ip_counter[request_ip];
			delete dns_spike_idx_2[request_ip];
		}

		# look for thresholds over the day duration

		if ( request_ip !in dns_ip_thresholds )
			dns_ip_thresholds[request_ip] = 1;

		dns_ip_thresholds[request_ip] += 1;

		n = |dns_ip_thresholds[request_ip]|;

		check_thresh = check_ip_threshold(dns_threshold, dns_ip_threshold_idx,
		    request_ip, n);

		if ( check_thresh ) {
			#print fmt ("IP [%s] has done %d lookups: %d", request_ip, dns_ip_thresholds[request_ip],n);
			msg = fmt("IP[%s] has done %s look ups: %d", request_ip,
			    dns_ip_thresholds[request_ip], n);
			NOTICE([
			    $note=DNS::Threshold,
			    $src=request_ip,
			    $msg=msg,
			    $identifier=cat(request_ip),
			    $suppress_for=1 min]);
		}
	} # if dns
} # end of event
