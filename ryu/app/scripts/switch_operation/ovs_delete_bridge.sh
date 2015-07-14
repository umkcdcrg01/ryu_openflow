#!/bin/bash

# The OVS bridge you wanna create
OVS_BRIDGE=ofpbr

sudo ovs-vsctl del-br $OVS_BRIDGE

sudo ovs-vsctl show