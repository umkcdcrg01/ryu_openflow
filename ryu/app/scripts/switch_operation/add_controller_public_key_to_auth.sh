#!/bin/bash
# add_controller_public_key_to_auth.sh
public_key='ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCYvpQbQimzOCEvmMak3WByazSCrhxy4cTZHCvDDdnP3UeTr2ge/E7W6cL+tlN1kfBP7RxKfzXU13QLTAyR+sLmOPsVQ5LozJyBwfCmpr1ybCS0zL2BpQfhBfFaz3t4dh9xdhDQ/+3F4JKUHJ5/gdXgW4DQBjloC2TyukshaGOilb7KsYtxhRf4G2euOvMhEHsBK3yJCVOjsl7vyua3py4t2r0zOPdrUylr+BwJhfE77SYYmjl10jmaA96uaWhDFlz7qIFChTbh+JjfNHA9ZrCLNwUs2a+pJChM7h65owFRcwie69XNhd0Y4n3uAxwd0Bo53Gmw1vDTjZhdDnGObdGD szb53@h4.openflowwithhadoop.ch-geni-net.instageni.gpolab.bbn.com'

cat >> ~/.ssh/authorized_keys << EOF
$public_key
EOF