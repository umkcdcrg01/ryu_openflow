#!/bin/sh

echo "run this script as root..."
# Make sure only root can run our script
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

echo "Updating your OS..."
sudo apt-get update

echo "Installing tools..."
sudo aptitude install dh-autoreconf libssl-dev openssl  build-essential fakeroot debhelper \
autoconf automake bzip2 graphviz python-all procps python-qt4 python-zopeinterface python-twisted-conch libtool -y

echo "downloding OVS 2.3.1 ..."
cd ~
wget http://openvswitch.org/releases/openvswitch-2.3.1.tar.gz
tar zxvf openvswitch-2.3.1.tar.gz && cd openvswitch-2.3.1

echo "Install OVS 2.3.1 ..."
DEB_BUILD_OPTIONS='parallel=8 nocheck' fakeroot debian/rules binary
cd ~
ls ~
dpkg -i openvswitch-common_2.3.1-1_amd64.deb  openvswitch-switch_2.3.1-1_amd64.deb

echo "Check if OVS has been succefully mounted"
lsmod |grep openvswitch

echo "check openvswitch version ..."
ovs-vsctl -V

echo "Check OVS process..."
ps -ef | grep ovs | grep -v grep

echo "done installation!"
