// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <map>
#include <vector>
#include <zeek/packet_analysis/Analyzer.h>

namespace zeek::packet_analysis::CAPWAP
	{

class CAPWAPAnalyzer : public Analyzer
	{
public:
	CAPWAPAnalyzer();
	~CAPWAPAnalyzer() override = default;

	bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;

	static zeek::packet_analysis::AnalyzerPtr Instantiate()
		{
		return std::make_shared<CAPWAPAnalyzer>();
		}

private:
	void FixIEEE802_11FCF(size_t len, const uint8_t* data);

	std::map<uint16_t, std::vector<uint8_t>> frag_bufs;
	};

	}
