//
// Created by andrey on 19.11.16.
//

#pragma once

#include <boost/lexical_cast.hpp>
#include <types/ethaddr.hh>
#include "Flow.hh"
#include <oxm/openflow_basic.hh>
#include "PacketParser.hh"
#include "Application.hh"
#include "Controller.hh"
#include "Loader.hh"
#include <unordered_map>
#include <unordered_set>


constexpr const int RULE_IDLE_TIMEOUT = 10;


namespace ethtypes{
	constexpr unsigned int IPv4 = 0x0800;
	constexpr unsigned int IPv6 = 0x86dd;
	constexpr unsigned int ARP = 0x0806;
};


namespace ipprotos {
	constexpr unsigned int TCP = 0x06;
	constexpr unsigned int UDP = 0x11;
	constexpr unsigned int ICMP = 0x01;
};


std::string ethAddrToString(const ethaddr & ethAddr) {
	return std::string(boost::lexical_cast<std::string>(ethAddr));
}


struct Data {
	void * ptr;
	size_t size;

	Data() {}
	Data(void * newPtr, size_t newSize): ptr(newPtr), size(newSize) {}
};


struct EthHdr {
	boost::endian::big_uint48_t dst;
	boost::endian::big_uint48_t src;
	boost::endian::big_uint16_t type;
};


struct IPv4Hdr {
	uint8_t ihl:4; // TODO: learn ipv4 protocol
	uint8_t version:4;
	uint8_t ecn:2;
	uint8_t dscp:6;
	boost::endian::big_uint16_t total_len;
	boost::endian::big_uint16_t identification;

	uint16_t flags:3;
	uint16_t fragment_offset_unordered:13;

	boost::endian::big_uint8_t ttl;
	boost::endian::big_uint8_t proto;
	boost::endian::big_uint16_t checksum;
	boost::endian::big_uint32_t src;
	boost::endian::big_uint32_t dst;
};


struct ICMPv4Hdr { ;
	uint8_t type;
	uint8_t code;
	boost::endian::big_uint16_t checksum;
	uint16_t unused;
	uint16_t mtu;
};


struct icmp_packet {
	EthHdr eth;
	IPv4Hdr ip;
	ICMPv4Hdr icmp;

};


struct Session {
	std::string srcEth;
	std::string dstEth;
	int ethType;
	long int srcIP;
	long int dstIP;
	int ipProto;
	int srcAppPort;
	int dstAppPort;

	Session(Packet & pkt);
	bool isSymmetric(const Session & s) const;
	bool isSame(const Session & s) const;
};



struct AccessInfo {
	std::unordered_set<int> tcpPorts;
	std::unordered_set<int> udpPorts;
	std::unordered_set<std::string> protocols;
};

typedef std::unordered_map<std::string, AccessInfo> UserPermission;
//typedef std::unordered_map<std::string, UserPermissions> Perm;


class AccessCtlApp : public Application {
	SIMPLE_APPLICATION(AccessCtlApp, "access-control")

	std::unordered_map<std::string, UserPermission> permUsers;
	UserPermission defaultPermission;
	std::unordered_map<uint64_t, Session> curSessions;

	void parseConfig(const Config & config);
	void parseUserPermission(const json11::Json & cfg, UserPermission & up);
	uint64_t hasSymmetricSession(const Session &s);
	uint64_t hasSameSession(const Session &s);
	uint64_t hasAccess(const Session &s, FlowPtr flw);
	bool hasPermission(const Session & s, UserPermission & up);
	void addSession(const Session & s, FlowPtr flw);
	void delSession(uint64_t cookie);
public:
	void init(Loader* loader, const Config& config) override;
public slots:
//	void onSwitchUp(SwitchConnectionPtr ofconn, of13::FeaturesReply fr);
//	void onSwitchDown(SwitchConnectionPtr ofconn);
	void flowRemoved(SwitchConnectionPtr ofconn, of13::FlowRemoved &flw);
//	void flowChangeState(Flow::State newState, uint64_t cookie);
};
