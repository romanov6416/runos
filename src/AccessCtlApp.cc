//
// Created by andrey on 19.11.16.
//

#include "AccessCtlApp.hh"

#include <glog/logging.h>
//#include <Controller.hh>
#include "api/PacketMissHandler.hh"
#include "api/Packet.hh"
#include "types/ethaddr.hh"
#include "api/TraceablePacket.hh"
#include "oxm/openflow_basic.hh"

REGISTER_APPLICATION(AccessCtlApp, {"controller", ""})

void AccessCtlApp::init(Loader *loader, const Config& config)
{
	Controller* ctrl = Controller::get(loader);
//	QObject::connect(ctrl, &Controller::switchUp, this, &AccessCtlApp::onSwitchUp);
	QObject::connect(ctrl, &Controller::switchDown, this, &AccessCtlApp::onSwitchDown);
	LOG(INFO) << "Hello, world!";
}

void AccessCtlApp::onSwitchUp(SwitchConnectionPtr ofconn, of13::FeaturesReply fr)
{
	LOG(INFO) << "Look! This is a switch " << fr.datapath_id();
}

void AccessCtlApp::onSwitchDown(SwitchConnectionPtr ofconn)
{
	LOG(INFO) << "Look! This is no switch";
}