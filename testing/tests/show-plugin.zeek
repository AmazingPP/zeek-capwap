# @TEST-EXEC: zeek -NN Zeek::CAPWAP |sed -e 's/version.*)/version)/g' | sed -e 's/, enabled)/)/g' >output
# @TEST-EXEC: btest-diff output
