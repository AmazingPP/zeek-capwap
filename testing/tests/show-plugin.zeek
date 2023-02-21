# @TEST-EXEC: zeek -NN Zeek::CAPWAP |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
