// See the file "COPYING" in the main distribution directory for copyright.

#include "CAPWAP.h"

#include <zeek/packet_analysis/protocol/iptunnel/IPTunnel.h>

#include "events.bif.h"

using namespace zeek::packet_analysis::CAPWAP;

CAPWAPAnalyzer::CAPWAPAnalyzer()
	: zeek::packet_analysis::Analyzer("CAPWAP")
	{
	}

bool CAPWAPAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	// CAPWAP always comes from a UDP connection, which means that session should always
	// be valid and always be a connection. Return a weird if we didn't have a session
	// stored.
	if ( ! packet->session )
		{
		Weird("capwap_missing_connection");
		return false;
		}
	else if ( AnalyzerViolated(packet->session) )
		return false;

	if ( packet->encap && packet->encap->Depth() >= BifConst::Tunnel::max_depth )
		{
		Weird("exceeded_tunnel_max_depth", packet);
		return false;
		}

	// This will be expanded based on the length of the options in the header,
	// but it will be at least this long.
	uint16_t hdr_size = 8;
	
	if ( hdr_size > len )
		{
		AnalyzerViolation("CAPWAP header truncation", packet->session, 
		                  reinterpret_cast<const char*>(data), len);
		return false;
		}

	// Validate that the version number is correct. According to the RFC, this
	// should always be zero, and anything else should be treated as an error.
	auto version = (data[0] & 0xF0) >> 4;
	if ( version != 0 )
		{
		Weird("capwap_invalid_version", packet, util::fmt("%d", version));
		return false;
		}

	// Double-check this one now that we know the actual full length of the header.
	size_t hdr_len = ((data[1] & 0xF8) >> 3) * 4;
	if ( hdr_len > len )
		{
		AnalyzerViolation("CAPWAP option header truncation", packet->session,
		                  reinterpret_cast<const char*>(data), len);
		return false;
		}

	uint16_t useless_frag_id = 0;
	if ( data[3] >> 7 )
		{
		// TODO: Need a better fragment reassembly implementation.
		auto last_frag = (data[3] & 0x40) >> 6;
		auto frag_id = ntohs(*reinterpret_cast<const uint16_t*>(data + 4));
		auto frag_offset = (ntohs(*reinterpret_cast<const uint16_t*>(data + 6)) >> 3) * 8;

		auto& buf = frag_bufs[frag_id];

		if ( frag_offset == 0 )
			{
			buf.resize(len);
			std::memcpy(buf.data(), data, len);
			}
		else
			{
			buf.resize(frag_offset + len);
			std::memcpy(buf.data() + hdr_len + frag_offset, data + len, len - hdr_len);
			}

		if ( ! last_frag )
			return false;
		
		useless_frag_id = frag_id;
		data = buf.data();
		len = buf.size();
		}

	int link_type; 
	auto wireless_binding_id = (data[2] & 0x3E) >> 1;
	auto payload_type = data[2] & 1;

	if ( ! payload_type )
		link_type = DLT_EN10MB;
	else if ( payload_type && wireless_binding_id == 1 )
		{
		link_type = DLT_IEEE802_11;
		// https://osqa-ask.wireshark.org/questions/55804/capwap-80111-data-header-fcf-swapped-why/
		// Some hardware sends out LWAPP(CAPWAP)-encapsulated 802.11 packets
		// with the control field byte swapped, We need fix it.
		FixIEEE802_11FCF(len - hdr_len, data + hdr_len);
		}
	else
		{
		Weird("capwap_not_support_wbid", packet, util::fmt("%d", wireless_binding_id));
		return false;
		}

	len -= hdr_len;
	data += hdr_len;

	// We've successfully parsed everything, so we might as well confirm this.
	AnalyzerConfirmation(packet->session);

	int encap_index = 0;
	static auto tunnel_type = static_cast<BifEnum::Tunnel::Type>(
		id::find_type("Tunnel::Type")->AsEnumType()->Lookup("Tunnel::CAPWAP"));
	auto inner_packet = packet_analysis::IPTunnel::build_inner_packet(
		packet, &encap_index, nullptr, len, data, link_type, tunnel_type,
		GetAnalyzerTag());

	bool fwd_ret_val = ForwardPacket(len, data, inner_packet.get(), link_type);

	if ( fwd_ret_val && capwap_packet )
		{
		EncapsulatingConn* ec = inner_packet->encap->At(encap_index);
		if ( ec && ec->ip_hdr )
			inner_packet->session->EnqueueEvent(capwap_packet, nullptr, packet->session->GetVal(),
			                                    ec->ip_hdr->ToPktHdrVal());
		}

	if ( useless_frag_id )
		frag_bufs.erase(useless_frag_id);

	return fwd_ret_val;
	}

void CAPWAPAnalyzer::FixIEEE802_11FCF(size_t len, const uint8_t* data)
	{
	if ( len < 2 )
		return;

	auto writeable_data = const_cast<uint8_t*>(data);
	std::swap(writeable_data[0], writeable_data[1]);
	}
