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

#include "Controller.hh"
#include "SwitchConnection.hh"
#include "Flow.hh"
#include "Common.hh"


REGISTER_APPLICATION(AccessCtlApp, {"controller", ""})



void AccessCtlApp::init(Loader *l, const Config& config)
{
	loader = l;
	parseConfig(config);
	Controller* ctrl = Controller::get(loader);

//	LOG(INFO) << "Homework app init";

	uint8_t table_no = ctrl->reserveTable(); // Your must push flowmod in this table
	table_no = table_no;
	ctrl->registerHandler(
		"access-control",
		[=](SwitchConnectionPtr connection) {

			return [=](Packet& pkt, FlowPtr flw, Decision decision) {

				// Write your code here
				//Below example code
				Session s(pkt);
				LOG(INFO) << s.srcEth << " " << s.dstEth;

				if (this->hasSymmetricSession(s)) {
					LOG(INFO) << "has access (symmetric)";
					return decision;
				}

				if (this->hasAccess(s, flw)) {
					LOG(INFO) << "has access (new)";
					this->addSession(s, flw);
					return decision;
				}

				// TODO: send ICMP error
				LOG(INFO) << "has not access";
				return decision.idle_timeout(std::chrono::seconds::zero()).drop().return_();
//				LOG(INFO) << "PacketIn captured";
//
//				ethaddr eth_dst = pkt.load(oxm::eth_dst());
//				if (eth_dst.to_number() % 2 == 0){
//					// I want to drop all packet that ended with zero bits
//					of13::FlowMod fm;
//					fm.command(of13::OFPFC_ADD);
//					fm.table_id(table_no); //  Push your flow in this table
//
//					fm.priority(1); // Priority must be higher than 0
//
//					std::stringstream ss;
//					ss << eth_dst;
//
//					of13::EthDst* ethDstToFlowMod = new of13::EthDst(
//						EthAddress( ss.str() )
//					); // Sorry for this
//
//					fm.add_oxm_field(ethDstToFlowMod);
//					connection->send(fm);
//				}
//
//				return decision;
			};
		});
}

void AccessCtlApp::onSwitchUp(SwitchConnectionPtr ofconn, of13::FeaturesReply fr)
{
	LOG(INFO) << "Look! This is a switch " << fr.datapath_id();
}

void AccessCtlApp::onSwitchDown(SwitchConnectionPtr ofconn)
{
	LOG(INFO) << "Look! This is no switch";
}

void AccessCtlApp::parseConfig(const Config &config) {
	auto appCfg = config_cd(config, "access-control");
	for (auto userAccess : appCfg["users-permissions"].object_items()) {
		auto &userMAC = userAccess.first;
		auto hostCfg = userAccess.second.object_items();
		parseUserPermission(hostCfg, permUsers[userMAC]);
	}
//	auto hostCfg = appCfg["default-permissions"].object_items();
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
//			LOG(INFO) << *(permUsers[userMAC][dstMAC].tcpPorts.begin());
//			LOG(INFO) << *(permUsers[userMAC][dstMAC].udpPorts.begin());
	}
}



bool AccessCtlApp::hasAccess(const Session &s, FlowPtr flw) {
	auto userEthIt = permUsers.find(s.srcEth);
	if (userEthIt == permUsers.cend())
		return false;

	if (hasPermission(s, userEthIt->second))
		return true;

	if (hasPermission(s, defaultPermission))
		return true;

	return false;
}



bool AccessCtlApp::hasPermission(const Session &s, UserPermission &up) {

	auto dstEthIt = up.find((s.dstEth));
	if (dstEthIt == up.cend())
		return false;

	AccessInfo & accessInfo = dstEthIt->second;

	LOG(INFO) << *(defaultPermission["ff:ff:ff:ff:ff:ff"].protocols.cbegin());
	LOG(INFO) << s.ipProto;

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


bool AccessCtlApp::hasSymmetricSession(const Session & incomingSession) {
	for (auto sInfo : curSessions)
		if (incomingSession.isSymmetric(sInfo.second))
			return true;
	return false;
}


void AccessCtlApp::addSession(const Session & s, FlowPtr flw) {
//	curSessions[flw->cookie()] = s;
	curSessions.insert(std::make_pair(flw->cookie(), s));
}


void AccessCtlApp::delSession(FlowPtr flw) {
	curSessions.erase(flw->cookie());
}






