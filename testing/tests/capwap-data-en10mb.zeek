# @TEST-EXEC: zeek -C -r $TRACES/capwap_http.pcap
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff tunnel.log
