# @TEST-EXEC: zeek -C -r $TRACES/capwap-jpg.pcapng frameworks/files/extract-all-files frameworks/files/hash-all-files
# @TEST-EXEC: btest-diff files.log
# @TEST-EXEC: btest-diff tunnel.log
