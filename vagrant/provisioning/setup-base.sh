#!/bin/sh
# debian frontend noninteractive disables user interaction
DEBIAN_FRONTEND=noninteractive sudo apt-get -qqy update
DEBIAN_FRONTEND=noninteractive sudo apt-get install -qqy git
DEBIAN_FRONTEND=noninteractive sudo apt-get install -qqy bridge-utils
DEBIAN_FRONTEND=noninteractive sudo apt-get install -qqy ebtables
DEBIAN_FRONTEND=noninteractive sudo apt-get install -qqy python-pip
DEBIAN_FRONTEND=noninteractive sudo apt-get install -qqy python-dev
DEBIAN_FRONTEND=noninteractive sudo apt-get install -qqy build-essential
DEBIAN_FRONTEND=noninteractive sudo apt-get install -qqy curl
DEBIAN_FRONTEND=noninteractive sudo apt-get install -qqy tcpdump
sudo pip install -U pbr
echo export LC_ALL=en_US.UTF-8 >> ~/.bash_profile
echo export LANG=en_US.UTF-8 >> ~/.bash_profile
# for a local deployment, this repo folder is shared between the host and the guests
if [ ! -d "dragonflow" ]; then
    git clone https://git.openstack.org/openstack/dragonflow.git
fi
# disable random ipv6 adresses
#echo "net.ipv6.conf.all.accept_ra=0" >> /etc/sysctl.conf
#echo "net.ipv6.conf.all.autoconf=0" >> /etc/sysctl.conf

sudo pip install --upgrade pip
#usage
#git clone git://github.com/robbyrussell/oh-my-zsh.git /home/vagrant/.oh-my-zsh
#apt-get -y install zsh
#sh -c "$(curl -fsSL https://raw.githubusercontent.com/robbyrussell/oh-my-zsh/master/tools/install.sh)"
#chsh -s /bin/zsh vagrant
echo "BASE SETUP DONE"
