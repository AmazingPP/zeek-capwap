module PacketAnalyzer::CAPWAP;

export {
	## The set of UDP ports used for CAPWAP Data traffic. Traffic using this
	## UDP destination port will attempt to be decapsulated. Note that if
	## if you customize this, you may still want to manually ensure that
	## :zeek:see:`likely_server_ports` also gets populated accordingly.
	const capwap_ports: set[port] = { 5247/udp } &redef;
}

redef likely_server_ports += { capwap_ports };

redef enum Tunnel::Type += { Tunnel::CAPWAP };

const DLT_EN10MB : count = 1;
const DLT_IEEE802_11 : count = 105;

event zeek_init() &priority=20
	{
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_CAPWAP, DLT_EN10MB, PacketAnalyzer::ANALYZER_ETHERNET);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_CAPWAP, DLT_IEEE802_11, PacketAnalyzer::ANALYZER_IEEE802_11);
	PacketAnalyzer::register_for_ports(PacketAnalyzer::ANALYZER_UDP, PacketAnalyzer::ANALYZER_CAPWAP, capwap_ports);
	}
