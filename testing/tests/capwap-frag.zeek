# @TEST-EXEC: zeek -C -r $TRACES/capwap-jpg.pcapng frameworks/files/extract-all-files frameworks/files/hash-all-files
# @TEST-EXEC: cat files.log | zeek-cut zeek-cut fuid source mime_type md5 sha1 >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff tunnel.log
