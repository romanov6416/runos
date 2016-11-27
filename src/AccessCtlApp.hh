//
// Created by andrey on 19.11.16.
//

#pragma once
#include "Application.hh"
#include "Controller.hh"
#include "Loader.hh"
//#include "Switch.hh"
//#include "fluid/of13"

class AccessCtlApp : public Application {
	SIMPLE_APPLICATION(AccessCtlApp, "access-control")
public:
	void init(Loader* loader, const Config& config) override;
public slots:
	void onSwitchUp(SwitchConnectionPtr ofconn, of13::FeaturesReply fr);
	void onSwitchDown(SwitchConnectionPtr ofconn);
};
