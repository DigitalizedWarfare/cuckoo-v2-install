#!/bin/bash
clear
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "     _____           _                __      _____    _____           _        _ _     "      
echo "    / ____|         | |               \ \    / /__ \  |_   _|         | |      | | |      "    
echo "   | |    _   _  ___| | _____   ___    \ \  / /   ) |   | |  _ __  ___| |_ __ _| | | ___ _ __ "
echo "   | |   | | | |/ __| |/ / _ \ / _ \    \ \/ /   / /    | | |  _ \/ __| __/ _  | | |/ _ \  __|"
echo "   | |___| |_| | (__|   < (_) | (_) |    \  /   / /_   _| |_| | | \__ \ || (_| | | |  __/ |   "
echo "    \_____\__,_|\___|_|\_\___/ \___/      \/   |____| |_____|_| |_|___/\__\__,_|_|_|\___|_|   "
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "	Author : Christian Marvel - Twitter : http://twiter.com/DigiWarfare"
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo " "
echo "Press ENTER Start the installation"
read install
clear

echo "Updating Operating System and Apt Sources"
sudo apt-get update -qq&&sudo apt-get upgrade -y -qq&&sudo apt-get dist-upgrade -y -qq

echo "Installing Python Base Files"
sudo apt-get install python python-pip python-dev libffi-dev libssl-dev python-libemu pkconfig build-essential checkinstall tesseract-ocr git-core autoconf libtool linux-headers-$(uname -r) -y -qq

echo "Installing Env and Python Setup Tools Files"
sudo apt-get install python-virtualenv python-setuptools libjpeg-dev zlib1g-dev swig libmagic-dev libconfig-dev libarchive-dev autoconf automake libjansson-dev openjdk-7-jre-headless -y -qq


echo "Building XRDP"
sudo apt-get install xrdp -y -qq
sudo apt-get install mate-core mate-desktop-environment mate-notification-daemon -y
cd /home/maint
echo mate-session >~/.xsession 

echo "Adding Elastic Search Sources"
sudo echo "deb http://packages.elasticsearch.org/elasticsearch/1.7/debian stable main" | sudo tee -a /etc/apt/sources.list.d/elasticsearch-1.7.list
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys D27D666CD88E42B4
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 40976EAF437D05B5
sudo apt-get update

echo "Installing Mongodb"
sudo apt-get install elasticsearch mongodb -y -qq

echo "Installing Postgresql"
sudo apt-get install mysql-server postgresql libpq-dev pkg-config -y -qq

echo "Installing Build Enviroment"
sudo apt-get install automake libtool make gcc -y -qq
sudo apt-get install phpmyadmin flex bison -y -qq

echo "Installing Git Software"
sudo apt-get install git -y -qq

echo "Install Deps for Web and SQL Connections"
sudo apt-get install gcc zip php-pear git redis-server make python-dev python-pip libxml2-dev libxslt1-dev zlib1g-dev php5-dev php5-xmlrpc libapache2-mod-php5 php5-mysql php5-json php5-redis curl gnupg-agent libmysqlclient-dev -y -qq

echo "Getting Current Yara from Git Source"
cd /opt
sudo git clone --recursive https://github.com/VirusTotal/yara.git /opt/yara
cd /opt/yara

echo "Building Yara"
sudo ./bootstrap.sh
sudo ./configure --enable-cuckoo --enable-magic --enable-dotnet
sudo make
sudo make install

echo "Building Yara Paython from Git Source"
cd /opt
sudo git clone --recursive https://github.com/VirusTotal/yara-python yara-python
cd yara-python
sudo python setup.py build
sudo python setup.py install

sudo chmod 777 /etc/ld.so.conf
sudo echo "/usr/local/lib" >> /etc/ld.so.conf
sudo ldconfig
sudo updatedb

echo "Building Libemu from Git Source"
cd /tmp/
sudo git clone --recursive https://github.com/buffer/libemu.git libemu
cd libemu
sudo autoreconf -v -i
sudo ./configure --enable-python-bindings --prefix=/opt/libemu
sudo make install
sudo ldconfig -n /opt/libemu/lib

echo "Building Pylibemu from Git Source"
sudo pip install pylibemu

cd /opt
sudo wget http://pkgs.fedoraproject.org/repo/pkgs/ssdeep/ssdeep-2.13.tar.gz/7608b794ce6b25fae8bb1c2f4d35b2ad/ssdeep-2.13.tar.gz -O ssdeep-2.13.tar.gz
sudo tar -xf ssdeep-2.13.tar.gz 
cd ssdeep-2.13
sudo ./configure
sudo make
sudo make install

echo "Updating Database and Copying libFuzzy"
sudo updatedb
sudo cp -Rv /usr/local/lib/libfuzzy.* /usr/lib/

echo "Installing PYDeep from Git Source"
cd /opt
sudo git clone --recursive https://github.com/kbandla/pydeep.git pydeep
cd pydeep
sudo python setup.py build
sudo python setup.py test
sudo python setup.py install

echo "Install DTrace from Git Source"
cd /opt
sudo git clone --recursive https://github.com/dtrace4linux/linux.git dtrace
cd dtrace
sudo tools/get-deps.pl
sudo make all
sudo make install
sudo make load

echo "Install ClamAV"
sudo apt-get install clamav clamav-daemon clamav-freshclam -y -qq

echo "Install XFonts"
sudo apt-get install wkhtmltopdf xvfb xfonts-100dpi -y -qq

echo "Building malheur from Git Source"
cd /opt
sudo git clone --recursive https://github.com/rieck/malheur.git malheur
cd malheur
sudo ./bootstrap
sudo ./configure --prefix=/usr
sudo make
sudo make check
sudo make install

echo "Installing Python-pil"
sudo apt-get install python-pil python-pefile -y -qq

echo "Building Virtual Enviroment"
cd /opt
sudo sh -c 'echo "deb http://download.virtualbox.org/virtualbox/debian $(lsb_release -cs) contrib" >> /etc/apt/sources.list.d/virtualbox.list'
sudo wget -q https://www.virtualbox.org/download/oracle_vbox.asc -O- | sudo apt-key add -
sudo apt-get update -qq
sudo apt-get install virtualbox-5.1 -y -qq

echo "Building Tor Enviroment"
sudo sh -c 'echo "deb http://deb.torproject.org/torproject.org trusty main" >> /etc/apt/sources.list.d/tor_source.list'
sudo sh -c 'echo "deb-src http://deb.torproject.org/torproject.org trusty main" >> /etc/apt/sources.list.d/tor_source.list'
sudo gpg --keyserver keys.gnupg.net --recv A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89
sudo gpg --export A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89 | sudo apt-key add -
sudo apt-get update
sudo apt-get install tor deb.torproject.org-keyring -y -qq

echo "Building TCP Dump"
sudo apt-get install tcpdump apparmor-utils -y -qq
sudo aa-disable /usr/sbin/tcpdump

sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
sudo apt-get install libcap2-bin -y -qq

echo "Building Distorm version from git source"
cd /opt
sudo git clone --recursive https://github.com/gdabah/distorm.git distorm
cd distorm
sudo python setup.py build
sudo python setup.py install

echo "Building PYCrypto from Git Source"
cd /opt
sudo git clone --recursive https://github.com/dlitz/pycrypto pycrypto
cd pycrypto
sudo python setup.py build
sudo python setup.py install

echo "Install ujson 1.35"
sudo -H pip install ujson

echo "Adding Cuckoo User to Virtualbox Group"
sudo usermod -a -G vboxusers maint
clear
echo "Now we need to run some commands as the Cucko User"
echo "After Typing Password Run the following Commands"
echo " "
echo "virtualenv venv"
echo ". venv/bin/activate"
echo "pip install -U pip setuptools"
echo "pip install -U cuckoo"
echo "cuckoo -d"
echo " "
echo "Type exit and press ENTER when done"

cd /home/maint
su maint

clear
echo "Build VM Cloak from Git Source"
sudo apt-get install python-yaml libyaml-dev libyaml-0-2 devscripts -y -qq
cd /opt
sudo git clone --recursive https://github.com/jbremer/vmcloak.git
cd vmcloak
sudo pip install -r requirements.txt
sudo python setup.py build
sudo python setup.py install

echo "Installing InetSim"
cd /opt
sudo wget http://www.inetsim.org/downloads/inetsim-1.2.6.tar.gz
sudo tar -xf inetsim-1.2.6.tar.gz
cd inetsim-1.2.6
sudo groupadd inetsim

echo "Building Suricata"
cd /opt
sudo add-apt-repository ppa:oisf/suricata-beta
sudo apt-get update -y -qq
sudo apt-get install suricata -y -qq
sudo echo "alert http any any -> any any (msg:\"FILE store all\"; filestore; noalert; sid:15; rev:1;)"  | sudo tee /etc/suricata/rules/cuckoo.rules
sudo cp /etc/suricata/suricata.yaml /etc/suricata/suricata-cuckoo.yaml
sudo chown maint:maint /etc/suricata/suricata-cuckoo.yaml

echo "Installing Emerging Threats from Git Source"
cd /opt
sudo git clone --recursive https://github.com/seanthegeek/etupdate.git
sudo cp etupdate/etupdate /usr/sbin
sudo /usr/sbin/etupdate -V

echo "Building Snort"
sudo apt-get install snort -qq
sudo chown -Rv maint:maint /home/maint/
sudo chmod -Rv 777 /etc/snort/
sudo chmod -Rv 777 /var/log/snort/

echo "Installing mitmproxy" 
sudo apt-get install mitmproxy -y -qq
sudo mitmproxy
sudo cp /home/maint/.mitmproxy/mitmproxy-ca-cert.p12 /home/maint/.cuckoo/analyzer/windows/bin/cert.p12

sudo vboxmanage hostonlyif create
sudo vboxmanage hostonlyif ipconfig vboxnet0 -ip 192.168.56.1
echo "Setting Vars"
sudo iptables -t nat -A POSTROUTING -o eth0 -s 192.168.56.0/24 -j MASQUERADE

echo "Configure IP Tables"
sudo iptables -P FORWARD DROP
sudo iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -s 192.168.56.0/24 -j ACCEPT
sudo iptables -A FORWARD -s 192.168.56.0/24 -d 192.168.56.0/24 -j ACCEPT
sudo iptables -A FORWARD -j LOG

echo 1 | sudo tee -a /proc/sys/net/ipv4/ip_forward
sudo sysctl -w net.ipv4.ip_forward=1

sudo mkdir -p /mnt/win/
sudo mkdir -p /mnt/linux/
sudo mkdir -p /mnt/mac/
sudo mkdir -p /mnt/android/

echo "Creating ISO Directorys"
sudo mkdir -p /home/maint/iso

echo "Building Wireshark"
sudo apt-get install wireshark -y -qq

