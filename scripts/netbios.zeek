module DNS;

# RCODE Response code - this 4 bit field is set as part of
#       responses.  The values have the following
#       interpretation:
#
#       0       No error condition
#
#       1       Format error - The name server was
#               unable to interpret the query.
#
#       2       Server failure - The name server was
#               unable to process this query due to a
#               problem with the name server.
#
#       3       Name Error - Meaningful only for
#               responses from an authoritative name
#               server, this code signifies that the
#               domain name referenced in the query does
#               not exist.
#
#       4       Not Implemented - The name server does
#               not support the requested kind of query.
#
#       5       Refused - The name server refuses to
#               perform the specified operation for
#               policy reasons.  For example, a name
#               server may not wish to provide the
#               information to the particular requester,
#               or a name server may not wish to perform
#               a particular operation (e.g., zone

export {
	global ptr_queries: table[addr] of opaque of cardinality &default=function(n: any): opaque of
	    cardinality {
		return hll_cardinality_init(0.001, 0.999);
	} &create_expire=1 day;
}

event DNS::log_dns(rec: DNS::Info)
{
	local request_ip: addr;
	local check_thresh: bool;

	request_ip = rec$id$orig_h;

	if ( ! rec?$qtype_name )
		print fmt("%s", rec);

	if ( rec$qtype_name != "PTR" )
		return;

	#if (! rec?$rcode)
	#print fmt ("%s %s %s %s",  rec$qtype, rec$qtype_name, rec$rcode, rec$rcode_name);
	#print fmt ("%s", rec) ;

	# for this we only care about external IPs 
	# hitting our dns_servers with all sorts of queries 
	#if (rec?$query && request_ip in dns_servers) {
	# return ; 
	#} 

	local lookup = rec$query;

	if ( request_ip !in ptr_queries ) {
		local cp: opaque of cardinality = hll_cardinality_init(0.001, 0.999);
		ptr_queries[request_ip] = cp;
	}
	hll_cardinality_add(ptr_queries[request_ip], lookup);
}

event zeek_done()
{
	for ( request_ip in ptr_queries ) {
		print fmt("ptr_queries: %s, %s", request_ip, double_to_count(
		    hll_cardinality_estimate(ptr_queries[request_ip])));
	}
}
