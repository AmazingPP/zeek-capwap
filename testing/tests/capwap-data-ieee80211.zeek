# @TEST-EXEC: zeek -C -r $TRACES/capwap_data.pcapng
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff tunnel.log
