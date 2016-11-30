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

#include <sstream>


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
		ipHeaderSize = 0;
	} else if (s.ethType == ethtypes::IPv4){
		icmp_pkt.ip.src = uint32_t(tpkt.watch(oxm::ipv4_dst()));
		icmp_pkt.ip.dst = uint32_t(tpkt.watch(oxm::ipv4_src()));
//		icmp_pkt.eth.src = ethaddr(tpkt.watch(oxm::eth_dst())).to_number();
//		icmp_pkt.eth.dst = ethaddr(tpkt.watch(oxm::eth_src())).to_number();
	} else {
		LOG(WARNING) << "ethernet type " << std::hex << "0x" << s.ethType << " does not support";
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


Session::Session(Packet &pkt, uint64_t cookie) {
	ethType = int(pkt.load(oxm::eth_type()));
	srcEth = ethAddrToString(pkt.load(oxm::eth_src()));
	dstEth = ethAddrToString(pkt.load(oxm::eth_dst()));

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
	cookies.insert(cookie);
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

void Session::addCookie(const uint64_t cookie) {
	cookies.insert(cookie);
}


void AccessCtlApp::init(Loader * loader, const Config& config)
{
	parseConfig(config);
	Controller * ctrl = Controller::get(loader);
	QObject::connect(ctrl, &Controller::flowRemoved,
	                 [&](SwitchConnectionPtr ofconn, of13::FlowRemoved & flw) {
		                 this->flowRemoved(ofconn, flw);
//		                 printf("in lambda: %p\n", &flw);
	                 });
	ctrl->registerHandler(
		"access-control",
		[=](SwitchConnectionPtr connection) {

			return [=](Packet& pkt, FlowPtr flw, Decision decision) {
				mutex.lock();
				LOG(INFO) << "lock";
//				uint8_t table_no = ctrl->reserveTable(); // Your must push flowmod in this table
//				table_no = table_no;
				Session s(pkt, flw->cookie());
				LOG(INFO) << s.srcEth << " ->" << s.dstEth;
				uint64_t c;
				auto tpkt1 = packet_cast<TraceablePacket>(pkt);
				LOG(INFO) << "incomming packet (cookie " << std::hex << "0x" << flw->cookie() << ", port " << uint32_t(tpkt1.watch(oxm::in_port())) << ")";
				LOG(INFO) << "tcpSrcPort " << s.srcAppPort << ", tcpDstPort " << s.dstAppPort;
				LOG(INFO) << std::hex << "0x" << s.ipProto;
//				return decision;
				c = this->hasSymmetricSession(s);
				if (c) {
					LOG(INFO) << "has access (symmetric cookie " << std::hex << "0x" << c << ")";
					return this->permit(decision);
//					return decision.idle_timeout(Decision::duration(RULE_IDLE_TIMEOUT));
				}

				c = this->hasSameSession(s);
				if (c) {
					LOG(INFO) << "has access (same cookie " << std::hex << "0x" << c << ")";;
					this->addSession(s);
					return this->permit(decision);
//					return decision.idle_timeout(Decision::duration(RULE_IDLE_TIMEOUT));
//					return decision;
				}

				c = this->hasAccess(s, flw);
				if (c) {
					LOG(INFO) << "has access (new cookie " << std::hex << "0x" << c << ")";;
					this->addSession(s);
					return this->permit(decision);
//					return decision.idle_timeout(Decision::duration(RULE_IDLE_TIMEOUT));
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
				free(data.ptr);
//				delete data.ptr;
				return this->forbid(decision);
//				return decision.drop().hard_timeout(std::chrono::seconds::zero()).return_();
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
	if (hasPermission(s, userEthIt->second)) {
		LOG(INFO) << "person";
		return flw->cookie();
	}
	if (hasPermission(s, defaultPermission)) {
		LOG(INFO) << "default";
		return flw->cookie();
	}
	return 0;
}


bool AccessCtlApp::hasPermission(const Session &s, UserPermission &up) {

	auto dstEthIt = up.find((s.dstEth));
	if (dstEthIt == up.cend())
		return false;

	AccessInfo & accessInfo = dstEthIt->second;
	LOG(INFO) << "ipProto " << s.ethType << ", tcpDstPort " << s.dstAppPort;
//	LOG(INFO) << "app src port" << s.dstAppPort << " and access tcp port " << *accessInfo.tcpPorts.cbegin();

	if (s.ethType == ethtypes::ARP) {
		return accessInfo.protocols.find("ARP") != accessInfo.protocols.cend();
	} else if (s.ethType == ethtypes::IPv4 || s.ethType == ethtypes::IPv6) {
		if (s.ipProto == ipprotos::ICMP) {
			return accessInfo.protocols.find("ICMP") != accessInfo.protocols.cend();
		} else if (s.ipProto == ipprotos::TCP) {
			return accessInfo.tcpPorts.find(s.dstAppPort) != accessInfo.tcpPorts.cend();
		} else if (s.ipProto == ipprotos::UDP) {
			return accessInfo.udpPorts.find(s.dstAppPort) != accessInfo.udpPorts.cend();
		} else
			LOG(WARNING) << "unknown ip protocol " << s.ethType;
	} else
		LOG(WARNING) << "unknown eth type " << s.ethType;
	return false;
}


uint64_t AccessCtlApp::hasSymmetricSession(const Session &incomingSession) {
	for (auto & s : curSessions)
		if (incomingSession.isSymmetric(s))
			return *(s.cookies.cbegin());
	return 0;
}


void AccessCtlApp::addSession(const Session & curS) {
	LOG(INFO) << "add cookie " << std::hex << "0x" << *(curS.cookies.cbegin());
	for (auto & s : curSessions)
		if (curS.isSame(s)) {
			s.addCookie(*curS.cookies.cbegin());
			return;
		}
	curSessions.push_back(curS);

	std::stringstream str;
	for (auto & s : curSessions)
		for (auto c : s.cookies)
			str << std::hex << "0x" << c << ", ";
	str << std::endl;
	LOG(INFO) << "sessions: " << str.str();
}


void AccessCtlApp::delSession(uint64_t cookie) {
	mutex.lock();
//	LOG(INFO) << "removed cookie " << std::hex << "0x" << cookie;
//	LOG(INFO) << "got cookie because it was deleted: " << std::hex << "0x" << cookie;
	for (auto it = curSessions.cbegin(); it != curSessions.cend(); ++it) {
		auto & s = *it;
		if (s.cookies.find(cookie) != s.cookies.cend()) {
			LOG(INFO) << "removed cookie " << std::hex << "0x" << cookie;
			curSessions.erase(it);
			break;
		}
	}
//
//	auto it = curSessions(cookie);
//	if (it != curSessions.cend()) {
//		LOG(INFO) << "remove cookie " << std::hex << "0x" << it->first;
//		for (auto & s : curSessions) {
//			if (it->second.isSame(s.second) or it->second.isSymmetric(s.second))
//				curSessions.erase(s.first);
//		}
//	}
////	curSessions.erase(cookie);
//////	curSessions.pop(cookie);
	std::stringstream str;
	for (auto & s : curSessions)
		for (auto c : s.cookies)
			str << std::hex << "0x" << c << ", ";
	str << std::endl;
	LOG(INFO) << "sessions: " << str.str();
	mutex.unlock();
}


void AccessCtlApp::flowRemoved(SwitchConnectionPtr ofconn, of13::FlowRemoved &flw) {
	if (flw.reason() == of13::OFPRR_HARD_TIMEOUT or flw.reason() == of13::OFPRR_IDLE_TIMEOUT)
		delSession(flw.cookie());
//	printf("in handler: %p\n", &flw);
}


uint64_t AccessCtlApp::hasSameSession(const Session &incomingSession) {
	for (auto & s : curSessions)
		if (incomingSession.isSame(s))
			return *(s.cookies.cbegin());
	return 0;
}

Decision AccessCtlApp::permit(Decision decision) {
	LOG(INFO) << "unlock";
	mutex.unlock();
	return decision.idle_timeout(Decision::duration(RULE_IDLE_TIMEOUT));
}

Decision AccessCtlApp::forbid(Decision decision) {
	LOG(INFO) << "unlock";
	mutex.unlock();
	return decision.drop().hard_timeout(std::chrono::seconds::zero()).return_();
}

Decision AccessCtlApp::miss(Decision decision) {
	return decision;
}


//of13::FlowMod fm;
//fm.priority(1);
//fm.table_id(table_no);
//fm.cookie(cookie - твоя кука);
//fm.flags(of13::OFPFF_SEND_FLOW_REM);
//conneciton->send(fm);