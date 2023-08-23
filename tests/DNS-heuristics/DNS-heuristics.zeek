# @TEST-EXEC: zeek -C -r $TRACES/ptr-dns-34.214.127.68.pcap-anon.pcap  ../../../scripts %INPUT
# @TEST-EXEC: btest-diff notice.log

