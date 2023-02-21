# @TEST-EXEC: zeek -C -r $TRACES/capwap_data.pcapng %INPUT >output
# @TEST-EXEC: btest-diff output

event capwap_packet(c: connection, inner: pkt_hdr)
	{
	print "capwap_packet", c$id, inner;
	}
