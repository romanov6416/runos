//
// Created by andrey on 19.11.16.
//

#include "AccessCtlApp.hh"

#include <glog/logging.h>

#include <sstream>
#include <boost/lexical_cast.hpp>

#include "api/Packet.hh"
#include "api/PacketMissHandler.hh"
#include "oxm/openflow_basic.hh"
#include "types/ethaddr.hh"
#include <boost/endian/arithmetic.hpp>
#include <api/TraceablePacket.hh>

#include "Controller.hh"
#include "SwitchConnection.hh"
#include "Flow.hh"
#include "Common.hh"


REGISTER_APPLICATION(AccessCtlApp, {"controller", ""})


unsigned short getChecksum(unsigned short *addr, int len) {
	register int sum = 0;
	u_short answer = 0;
	register u_short *w = addr;
	register int nleft = len;
	/*
	* Our algorithm is simple, using a 32 bit accumulator (sum), we add
	* sequential 16 bit words to it, and at the end, fold back all the
	* carry bits from the top 16 bits into the lower 16 bits.
	*/
	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}
	/* mop up an odd byte, if necessary */
	if (nleft == 1)
	{
		*(u_char *) (&answer) = *(u_char *) w;
		sum += answer;
	}
	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
	sum += (sum >> 16); /* add carry */
	answer = ~sum; /* truncate to 16 bits */
	return (answer);
}


Data getICMPerror(Packet &inPkt, Session &s) {

	auto inPktSize = packet_cast<SerializablePacket&>(inPkt).total_bytes();
	uint8_t* inPktData = new uint8_t[inPktSize];
	packet_cast<SerializablePacket&>(inPkt).serialize_to(inPktSize, inPktData);
	size_t ipHeaderSize = static_cast<size_t>((inPktData[14] & 15) * 4);
	auto resultOutPktSize = sizeof(icmp_packet) + ipHeaderSize + 8;

	auto tpkt = packet_cast<TraceablePacket>(inPkt);

	icmp_packet icmp_pkt;

	icmp_pkt.eth.type = 0x0800;
	icmp_pkt.eth.src = ethaddr(tpkt.watch(oxm::eth_src())).to_number();
	icmp_pkt.eth.dst = ethaddr(tpkt.watch(oxm::eth_dst())).to_number();

	if (s.ethType == ethtypes::ARP) {
		icmp_pkt.ip.src = uint32_t(tpkt.watch(oxm::arp_tpa()));
		icmp_pkt.ip.dst = uint32_t(tpkt.watch(oxm::arp_spa()));
	} else if (s.ethType == ethtypes::IPv4 || s.ethType == ethtypes::IPv6){
		icmp_pkt.ip.src = uint32_t(tpkt.watch(oxm::ipv4_dst()));
		icmp_pkt.ip.dst = uint32_t(tpkt.watch(oxm::ipv4_src()));
//		icmp_pkt.eth.src = ethaddr(tpkt.watch(oxm::eth_dst())).to_number();
//		icmp_pkt.eth.dst = ethaddr(tpkt.watch(oxm::eth_src())).to_number();
	} else {
		LOG(WARNING) << "unknown ethernet type " << std::hex << "0x" << s.ethType;
		return Data(nullptr, 0);
	}
	icmp_pkt.ip.ttl = 255;
	icmp_pkt.ip.proto = 1;
	icmp_pkt.ip.identification = 0;
	icmp_pkt.ip.total_len = resultOutPktSize - sizeof(EthHdr);
	icmp_pkt.ip.checksum = getChecksum((unsigned short *)(&icmp_pkt.ip), sizeof(IPv4Hdr));
	icmp_pkt.ip.version = 4;
	icmp_pkt.ip.ihl = 5;
	icmp_pkt.ip.dscp = 0;
	icmp_pkt.ip.ecn = 0;
	icmp_pkt.ip.flags = 0;
	icmp_pkt.ip.fragment_offset_unordered = 0;

	icmp_pkt.icmp.type = 3;
	icmp_pkt.icmp.code = 10;
	icmp_pkt.icmp.checksum = getChecksum((unsigned short *)(&icmp_pkt.icmp), sizeof(ICMPv4Hdr));
	icmp_pkt.icmp.unused = 0;
	icmp_pkt.icmp.mtu = 0;


	uint8_t* data = new uint8_t[resultOutPktSize];
	// copy packet to data
	memmove(data, &icmp_pkt, sizeof(icmp_pkt));
	memmove(data + sizeof(icmp_pkt), inPktData + 14, ipHeaderSize + 8);
	return Data(data, resultOutPktSize);
}


Session::Session(Packet & pkt) {
	ethType = int(pkt.load(oxm::eth_type()));
//	if (ethType == ethtypes::ARP) {
//		srcEth = ethAddrToString(pkt.load(oxm::arp_sha()));
//		dstEth = ethAddrToString(pkt.load(oxm::arp_tha()));
//	} else {
		srcEth = ethAddrToString(pkt.load(oxm::eth_src()));
		dstEth = ethAddrToString(pkt.load(oxm::eth_dst()));
//	}
	LOG(INFO) << srcEth << " ->" << dstEth;


	if (ethType == ethtypes::IPv4) {
		ipProto = int(pkt.load(oxm::ip_proto()));
		srcIP = uint32_t(pkt.load(oxm::ipv4_src()));
		dstIP = uint32_t(pkt.load(oxm::ipv4_dst()));
		if (ipProto == ipprotos::TCP) {
			srcAppPort = int(pkt.load(oxm::tcp_src()));
			dstAppPort = int(pkt.load(oxm::tcp_dst()));
		} else if (ipProto == ipprotos::UDP) {
			srcAppPort = int(pkt.load(oxm::udp_src()));
			dstAppPort = int(pkt.load(oxm::udp_dst()));
		} else {
			srcAppPort = dstAppPort = -1;
		}
	} else {
		ipProto = srcAppPort = dstAppPort = -1;
		srcIP = dstIP = -1;
	}
}


bool Session::isSymmetric(const Session & s) const {
	return srcEth == s.dstEth && dstEth == s.srcEth &&
	       ethType == s.ethType && ipProto == s.ipProto &&
	       srcIP == s.dstIP && dstIP == s.srcIP &&
	       srcAppPort == s.dstAppPort && dstAppPort == s.srcAppPort;
}

bool Session::isSame(const Session & s) const {
	return srcEth == s.srcEth && dstEth == s.dstEth &&
	       ethType == s.ethType && ipProto == s.ipProto &&
	       srcIP == s.srcIP && dstIP == s.dstIP &&
	       srcAppPort == s.srcAppPort && dstAppPort == s.dstAppPort;
}


void AccessCtlApp::init(Loader * loader, const Config& config)
{
	parseConfig(config);
	Controller * ctrl = Controller::get(loader);
	QObject::connect(ctrl, &Controller::flowRemoved,
	                 [=](SwitchConnectionPtr ofconn, of13::FlowRemoved flw) {
		                 this->flowRemoved(ofconn, flw);
	                 });
	ctrl->registerHandler(
		"access-control",
		[=](SwitchConnectionPtr connection) {

			return [=](Packet& pkt, FlowPtr flw, Decision decision) {
				Session s(pkt);
				LOG(INFO) << s.srcEth << " ->" << s.dstEth;
				uint64_t c;

				c = this->hasSymmetricSession(s);
				if (c) {
					LOG(INFO) << "has access (symmetric cookie " << std::hex << "0x" << c << ")";
					return decision.idle_timeout(Decision::duration(RULE_IDLE_TIMEOUT));
				}

				c = this->hasSameSession(s);
				if (c) {
					LOG(INFO) << "has access (same cookie " << std::hex << "0x" << c << ")";;
					return decision.idle_timeout(Decision::duration(RULE_IDLE_TIMEOUT));
				}

				c = this->hasAccess(s, flw);
				if (c) {
					LOG(INFO) << "has access (new cookie " << std::hex << "0x" << c << ")";;
					this->addSession(s, flw);
					return decision.idle_timeout(Decision::duration(RULE_IDLE_TIMEOUT));
				}

				LOG(INFO) << "has not access";
				auto tpkt = packet_cast<TraceablePacket>(pkt);
				Data data = getICMPerror(pkt, s);

				of13::PacketOut out;
				out.buffer_id(OFP_NO_BUFFER);
				out.data(data.ptr, data.size);
				of13::OutputAction action(uint32_t(tpkt.watch(oxm::in_port())), 0);
				out.add_action(action);
				connection->send(out);
				return decision.hard_timeout(std::chrono::seconds::zero()).drop().return_();
			};
		}
	);
}


void AccessCtlApp::parseConfig(const Config &config) {
	auto appCfg = config_cd(config, "access-control");
	for (auto userAccess : appCfg["users-permissions"].object_items()) {
		auto &userMAC = userAccess.first;
		auto hostCfg = userAccess.second.object_items();
		parseUserPermission(hostCfg, permUsers[userMAC]);
	}
	parseUserPermission(appCfg["default-permissions"], defaultPermission);
}


void AccessCtlApp::parseUserPermission(const json11::Json & cfg, UserPermission &up) {
	for (auto hostAccessInfo : cfg.object_items()) {
		auto dstMAC = hostAccessInfo.first;
		AccessInfo & access = up[dstMAC];
		for (auto tcpPort : hostAccessInfo.second["tcp-ports"].array_items())
			access.tcpPorts.insert(tcpPort.int_value());
		for (auto udpPort : hostAccessInfo.second["udp-ports"].array_items())
			access.udpPorts.insert(udpPort.int_value());
		for (auto proto : hostAccessInfo.second["protocols"].array_items())
			access.protocols.insert(proto.string_value());
	}
}



uint64_t AccessCtlApp::hasAccess(const Session &s, FlowPtr flw) {
	auto userEthIt = permUsers.find(s.srcEth);
	if (userEthIt == permUsers.cend())
		return 0;
	if (hasPermission(s, userEthIt->second))
		return flw->cookie();
	if (hasPermission(s, defaultPermission))
		return flw->cookie();
	return 0;
}



bool AccessCtlApp::hasPermission(const Session &s, UserPermission &up) {

	auto dstEthIt = up.find((s.dstEth));
	if (dstEthIt == up.cend())
		return false;

	AccessInfo & accessInfo = dstEthIt->second;

	if (s.ethType == ethtypes::ARP) {
		return accessInfo.protocols.find("ARP") != accessInfo.protocols.cend();
	} else if (s.ethType == ethtypes::IPv4 || s.ethType == ethtypes::IPv6) {
		if (s.ipProto == ipprotos::ICMP) {
			return accessInfo.protocols.find("ICMP") != accessInfo.protocols.cend();
		} else if (s.ipProto == ipprotos::TCP) {
			return accessInfo.tcpPorts.find(s.dstAppPort) == accessInfo.tcpPorts.cend();
		} else if (s.ipProto == ipprotos::UDP) {
			return accessInfo.udpPorts.find(s.dstAppPort) == accessInfo.udpPorts.cend();
		} else
			LOG(WARNING) << "unknown ip protocol " << s.ethType;
	} else
		LOG(WARNING) << "unknown eth type " << s.ethType;
	return false;
}


uint64_t AccessCtlApp::hasSymmetricSession(const Session &incomingSession) {
	for (auto sInfo : curSessions)
		if (incomingSession.isSymmetric(sInfo.second))
			return sInfo.first;
	return 0;
}


void AccessCtlApp::addSession(const Session & s, FlowPtr flw) {
	LOG(INFO) << "add cookie " << std::hex << "0x" << flw->cookie();
	curSessions.insert(std::make_pair(flw->cookie(), s));
	LOG(INFO) << "sessions count " << curSessions.size();
}


void AccessCtlApp::delSession(uint64_t cookie) {
//	LOG(INFO) << "removed cookie " << std::hex << "0x" << cookie;
//	LOG(INFO) << "got cookie because it was deleted: " << std::hex << "0x" << cookie;
	auto it = curSessions.find(cookie);
	if (it != curSessions.cend())
		LOG(INFO) << "remove cookie" << std::hex << it->first;
	curSessions.erase(cookie);
	LOG(INFO) << "sessions count " << curSessions.size();
}


void AccessCtlApp::flowRemoved(SwitchConnectionPtr ofconn, of13::FlowRemoved &flw) {
	delSession(flw.cookie());
}


uint64_t AccessCtlApp::hasSameSession(const Session &incomingSession) {
	for (auto sInfo : curSessions)
		if (incomingSession.isSame(sInfo.second))
			return sInfo.first;
	return 0;
}
