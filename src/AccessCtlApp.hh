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
//#include "Switch.hh"
//#include "fluid/of13


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


struct Session {
	std::string srcEth;
	std::string dstEth;
	int ethType;
	int ipProto;
	int srcAppPort;
	int dstAppPort;

	Session(Packet & pkt) {
		srcEth = ethAddrToString(pkt.load(oxm::eth_src()));
		dstEth = ethAddrToString(pkt.load(oxm::eth_dst()));
		ethType = int(pkt.load(oxm::eth_type()));

		LOG(INFO) << "ethtype " << ethType;

		if (ethType == ethtypes::IPv4 || ethType == ethtypes::IPv6) {
			ipProto = pkt.load(oxm::ip_proto());
			if (ipProto == ipprotos::TCP) {
				srcAppPort = pkt.load(oxm::tcp_src());
				dstAppPort = pkt.load(oxm::tcp_dst());
			} else if (ipProto == ipprotos::UDP) {
				srcAppPort = pkt.load(oxm::udp_src());
				dstAppPort = pkt.load(oxm::udp_dst());
			} else {
				srcAppPort = dstAppPort = -1;
			}
		} else {
			ipProto = srcAppPort = dstAppPort = -1;
		}
	}

	bool isSymmetric(const Session & s) const {
		return srcEth == s.dstEth && dstEth == s.srcEth &&
		       ethType == s.ethType && ipProto == s.ipProto &&
		       srcAppPort == s.dstAppPort && dstAppPort == s.srcAppPort;
	}
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

	Loader* loader;
	std::unordered_map<std::string, UserPermission> permUsers;
	UserPermission defaultPermission;
	std::unordered_map<uint64_t, Session> curSessions;

	void parseConfig(const Config & config);
	void parseUserPermission(const json11::Json & cfg, UserPermission & up);
	bool hasSymmetricSession(const Session & s);
	bool hasAccess(const Session &s, FlowPtr flw);
	bool hasPermission(const Session & s, UserPermission & up);
	void addSession(const Session & s, FlowPtr flw);
	void delSession(FlowPtr flw);
public:
	void init(Loader* loader, const Config& config) override;
public slots:
	void onSwitchUp(SwitchConnectionPtr ofconn, of13::FeaturesReply fr);
	void onSwitchDown(SwitchConnectionPtr ofconn);

};
