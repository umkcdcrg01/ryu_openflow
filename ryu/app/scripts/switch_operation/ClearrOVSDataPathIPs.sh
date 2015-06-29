#!/bin/bash

ETHARRAY=("eth1" "eth2" "eth3")

for i in "${ETHARRAY[@]}"
do
	sudo ifconfig $i 0
done
