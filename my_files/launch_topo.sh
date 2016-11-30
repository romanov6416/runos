#!/usr/bin/env bash
sudo mn -c
sudo mn --custom custom_topo.py --topo customtopo3  --controller 'remote,ip=0.0.0.0,port=6653' --switch ovsk,protocols=OpenFlow13