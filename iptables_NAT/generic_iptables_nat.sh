#!/bin/bash

# thanks to http://centossrv.com/linux-router.shtml
# This script assumes;
# Network address on LAN:	192.168.1.0
# Subnet mask on LAN:		255.255.255.0

LOCALNET_ADDR=192.168.1.0
LOCALNET_MASK=255.255.255.0
LOCALNET=$LOCALNET_ADDR/$LOCALNET_MASK

#---------------------------------------#
# �ݒ�J�n                              #
#---------------------------------------#

# WAN�C���^�t�F�[�X����`
WAN_IF=`route -4 | grep default | sed 's/[\t ]\+/\t/g' | cut -f8`

# LAN�C���^�t�F�[�X����`
LAN_IF=`route -4 | grep $LOCALNET_ADDR | sed 's/[\t ]\+/\t/g' | cut -f8`

# ���J�T�[�o�[�v���C�x�[�gIP�A�h���X��`
# SERVER=192.168.1.3

#---------------------------------------#
# �ݒ�I��                              #
#---------------------------------------#

# ���z�X�g�v���C�x�[�gIP�A�h���X�擾
LAN_IP=`ifconfig $LAN_IF | grep 'inet ' | sed -e 's/^.*inet //' -e 's/ .*//'`

# ���z�X�g�O���[�o��IP�A�h���X�擾
WAN_IP=`ifconfig $WAN_IF | grep 'inet ' | sed -e 's/^.*inet //' -e 's/ .*//'`


#---------------------------------------#
# ���m�F                              #
#---------------------------------------#
echo "LAN is $LOCALNET. (That is what you said!)"
echo "Therefore, LAN is on $LAN_IF and its IP address is $LAN_IP."
echo ""
echo "WAN is the interface with default route."
echo "Therefore, WAN is on $WAN_IF and its IP address is $WAN_IP, currently."
echo ""
echo ""
echo ""
echo "Press Enter to proceed..."
read Wait


# �ǂݍ��ݑΏۃ��W���[���ǉ�
sed -i '/IPTABLES_MODULES/d' /etc/sysconfig/iptables-config
modinfo ip_nat_pptp > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "IPTABLES_MODULES=\"ip_conntrack_ftp ip_nat_ftp ip_nat_pptp\"" >> /etc/sysconfig/iptables-config
else
    echo "IPTABLES_MODULES=\"ip_conntrack_ftp ip_nat_ftp\"" >> /etc/sysconfig/iptables-config
fi

# �p�P�b�g�]����~
# �����[���ݒ蒆�̃p�P�b�g�ʉߖh�~
sysctl -w net.ipv4.ip_forward=0 > /dev/null

# �f�t�H���g���[��(�ȍ~�̃��[���Ƀ}�b�`���Ȃ������ꍇ�ɓK�p���郋�[��)�ݒ�
IPTABLES_CONFIG_NAT=`mktemp`
IPTABLES_CONFIG_FILTER=`mktemp`
echo "*nat" >> $IPTABLES_CONFIG_NAT
echo ":PREROUTING ACCEPT [0:0]" >> $IPTABLES_CONFIG_NAT
echo ":POSTROUTING ACCEPT [0:0]" >> $IPTABLES_CONFIG_NAT
echo ":OUTPUT ACCEPT [0:0]" >> $IPTABLES_CONFIG_NAT
echo "*filter" >> $IPTABLES_CONFIG_FILTER
echo ":INPUT DROP [0:0]" >> $IPTABLES_CONFIG_FILTER       # ��M�͂��ׂĔj��
echo ":FORWARD DROP [0:0]" >> $IPTABLES_CONFIG_FILTER     # �ʉ߂͂��ׂĔj��
echo ":OUTPUT ACCEPT [0:0]" >> $IPTABLES_CONFIG_FILTER    # ���M�͂��ׂċ���
echo ":ACCEPT_COUNTRY - [0:0]" >> $IPTABLES_CONFIG_FILTER # �w�肵��������̃A�N�Z�X������
echo ":DROP_COUNTRY - [0:0]" >> $IPTABLES_CONFIG_FILTER   # �w�肵��������̃A�N�Z�X��j��
echo ":LOG_FRAGMENT - [0:0]" >> $IPTABLES_CONFIG_FILTER   # �t���O�����g�����ꂽ�p�P�b�g�̓��O���L�^���Ĕj��
echo ":LOG_INGRESS - [0:0]" >> $IPTABLES_CONFIG_FILTER    # ���M��IP�A�h���X��LAN�l�b�g���[�N�͈͊O�̃A�N�Z�X�̓��O���L�^���Ĕj��
echo ":LOG_PINGDEATH - [0:0]" >> $IPTABLES_CONFIG_FILTER  # Ping of Death�U���̓��O���L�^���Ĕj��
echo ":LOG_SPOOFING - [0:0]" >> $IPTABLES_CONFIG_FILTER   # WAN����̑��M�����v���C�x�[�gIP�A�h���X�̃p�P�b�g�̓��O���L�^���Ĕj��

# �p�XMTU���Ώ�
echo "-A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu" >> $IPTABLES_CONFIG_FILTER

# SYN Cookies��L���ɂ���
# ��TCP SYN Flood�U���΍�
sysctl -w net.ipv4.tcp_syncookies=1 > /dev/null
sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
echo "net.ipv4.tcp_syncookies=1" >> /etc/sysctl.conf

# �u���[�h�L���X�g�A�h���X��ping�ɂ͉������Ȃ�
# ��Smurf�U���΍�
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1 > /dev/null
sed -i '/net.ipv4.icmp_echo_ignore_broadcasts/d' /etc/sysctl.conf
echo "net.ipv4.icmp_echo_ignore_broadcasts=1" >> /etc/sysctl.conf

# ICMP Redirect�p�P�b�g�͋���
sed -i '/net.ipv4.conf.*.accept_redirects/d' /etc/sysctl.conf
for dev in `ls /proc/sys/net/ipv4/conf/`
do
    sysctl -w net.ipv4.conf.$dev.accept_redirects=0 > /dev/null
    echo "net.ipv4.conf.$dev.accept_redirects=0" >> /etc/sysctl.conf
done

# Source Routed�p�P�b�g�͋���
sed -i '/net.ipv4.conf.*.accept_source_route/d' /etc/sysctl.conf
for dev in `ls /proc/sys/net/ipv4/conf/`
do
    sysctl -w net.ipv4.conf.$dev.accept_source_route=0 > /dev/null
    echo "net.ipv4.conf.$dev.accept_source_route=0" >> /etc/sysctl.conf
done

# �t���O�����g�����ꂽ�p�P�b�g�̓��O���L�^���Ĕj��
echo "-A LOG_FRAGMENT -j LOG --log-tcp-options --log-ip-options --log-prefix \"[IPTABLES FRAGMENT] : \"" >> $IPTABLES_CONFIG_FILTER
echo "-A LOG_FRAGMENT -j DROP" >> $IPTABLES_CONFIG_FILTER
echo "-A INPUT -f -j LOG_FRAGMENT" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -f -j LOG_FRAGMENT" >> $IPTABLES_CONFIG_FILTER

# WAN����̑��M�����v���C�x�[�gIP�A�h���X�̃p�P�b�g�̓��O���L�^���Ĕj��
# ��IP spoofing�U���΍�
echo "-A LOG_SPOOFING -j LOG --log-tcp-options --log-ip-options --log-prefix \"[IPTABLES SPOOFING] : \"" >> $IPTABLES_CONFIG_FILTER
echo "-A LOG_SPOOFING -j DROP" >> $IPTABLES_CONFIG_FILTER
echo "-A INPUT -i $WAN_IF -s 127.0.0.0/8    -j LOG_SPOOFING" >> $IPTABLES_CONFIG_FILTER
echo "-A INPUT -i $WAN_IF -s 10.0.0.0/8     -j LOG_SPOOFING" >> $IPTABLES_CONFIG_FILTER
echo "-A INPUT -i $WAN_IF -s 172.16.0.0/12  -j LOG_SPOOFING" >> $IPTABLES_CONFIG_FILTER
echo "-A INPUT -i $WAN_IF -s 192.168.0.0/16 -j LOG_SPOOFING" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -i $WAN_IF -s 127.0.0.0/8    -j LOG_SPOOFING" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -i $WAN_IF -s 10.0.0.0/8     -j LOG_SPOOFING" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -i $WAN_IF -s 172.16.0.0/12  -j LOG_SPOOFING" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -i $WAN_IF -s 192.168.0.0/16 -j LOG_SPOOFING" >> $IPTABLES_CONFIG_FILTER

# WAN�Ƃ�NetBIOS�֘A�̃A�N�Z�X�̓��O���L�^�����ɔj��
echo "-A INPUT -i $WAN_IF -p tcp -m multiport --dports 135,137,138,139,445 -j DROP" >> $IPTABLES_CONFIG_FILTER
echo "-A INPUT -i $WAN_IF -p udp -m multiport --dports 135,137,138,139,445 -j DROP" >> $IPTABLES_CONFIG_FILTER
echo "-A OUTPUT -o $WAN_IF -p tcp -m multiport --sports 135,137,138,139,445 -j DROP" >> $IPTABLES_CONFIG_FILTER
echo "-A OUTPUT -o $WAN_IF -p udp -m multiport --sports 135,137,138,139,445 -j DROP" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -i $WAN_IF -p tcp -m multiport --dports 135,137,138,139,445 -j DROP" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -i $WAN_IF -p udp -m multiport --dports 135,137,138,139,445 -j DROP" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -o $WAN_IF -p tcp -m multiport --sports 135,137,138,139,445 -j DROP" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -o $WAN_IF -p udp -m multiport --sports 135,137,138,139,445 -j DROP" >> $IPTABLES_CONFIG_FILTER

# 1�b�Ԃ�4��𒴂���ping�̓��O���L�^���Ĕj��
echo "-A LOG_PINGDEATH -m limit --limit 1/s --limit-burst 4 -j ACCEPT" >> $IPTABLES_CONFIG_FILTER
echo "-A LOG_PINGDEATH -j LOG --log-prefix \"[IPTABLES PINGDEATH] : \"" >> $IPTABLES_CONFIG_FILTER
echo "-A LOG_PINGDEATH -j DROP" >> $IPTABLES_CONFIG_FILTER
echo "-A INPUT -p icmp --icmp-type echo-request -j LOG_PINGDEATH" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -o ! $WAN_IF -p icmp --icmp-type echo-request -j LOG_PINGDEATH" >> $IPTABLES_CONFIG_FILTER

# ���M��IP�A�h���X��LAN�l�b�g���[�N�͈͊O�̃A�N�Z�X�̓��O���L�^���Ĕj��
# ��Ingress�΍�
echo "-A LOG_INGRESS -j LOG --log-tcp-options --log-ip-options --log-prefix \"[IPTABLES INGRESS] : \"" >> $IPTABLES_CONFIG_FILTER
echo "-A LOG_INGRESS -j DROP" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -i $LAN_IF -s ! $LOCALNET -j LOG_INGRESS" >> $IPTABLES_CONFIG_FILTER

# ���z�X�g����̃A�N�Z�X�����ׂċ���
echo "-A INPUT -i lo -j ACCEPT" >> $IPTABLES_CONFIG_FILTER

# ACCEPT_WHITELIST_MAKE�֐���`
# �w�肳�ꂽ�T�u�l�b�g����̃A�N�Z�X�������郆�[�U��`�`�F�C���쐬
ACCEPT_WHITELIST_MAKE

# LAN����̃A�N�Z�X�����ׂċ���
echo "-A INPUT -i $LAN_IF -j ACCEPT" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -i $LAN_IF -j ACCEPT" >> $IPTABLES_CONFIG_FILTER

## LAN����̃C���^�[�l�b�g�ւ̓����ڑ����\�ɂ���
## ��IP masquerade(NAPT) 
#WAN_INF=`ls /etc/sysconfig/network-scripts/ifcfg-*|sed -e 's/^.*ifcfg-\([^ ]*\).*$/\1/p' -e d|grep ppp`
#for dev in $WAN_INF
#do
#    echo "-A POSTROUTING -o $dev -j MASQUERADE" >> $IPTABLES_CONFIG_NAT
#         
#done

echo "-A POSTROUTING -s $LOCALNET -o $WAN_IF -j MASQUERADE" >> $IPTABLES_CONFIG_NAT

# LAN����s�����A�N�Z�X�ɑ΂���WAN����̕ԓ��A�N�Z�X������
echo "-A INPUT -i $WAN_IF -m state --state ESTABLISHED,RELATED -j ACCEPT" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -i $WAN_IF -m state --state ESTABLISHED,RELATED -j ACCEPT" >> $IPTABLES_CONFIG_FILTER

# DNS�����A�N�Z�X������
echo "-A INPUT -p udp --sport 53 -j ACCEPT" >> $IPTABLES_CONFIG_FILTER

# WAN����̕K�{ICMP�p�P�b�g������
echo "-A INPUT -p icmp --icmp-type destination-unreachable -j ACCEPT" >> $IPTABLES_CONFIG_FILTER
echo "-A INPUT -p icmp --icmp-type source-quench -j ACCEPT" >> $IPTABLES_CONFIG_FILTER
echo "-A INPUT -p icmp --icmp-type time-exceeded -j ACCEPT" >> $IPTABLES_CONFIG_FILTER
echo "-A INPUT -p icmp --icmp-type parameter-problem -j ACCEPT" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -p icmp --icmp-type destination-unreachable -j ACCEPT" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -p icmp --icmp-type source-quench -j ACCEPT" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -p icmp --icmp-type time-exceeded -j ACCEPT" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -p icmp --icmp-type parameter-problem -j ACCEPT" >> $IPTABLES_CONFIG_FILTER

# 113�ԃ|�[�g(IDENT)�ւ̃A�N�Z�X�ɂ͋��ۉ���
# �����[���T�[�o���̃��X�|���X�ቺ�h�~
echo "-A INPUT -p tcp --dport 113 -j REJECT --reject-with tcp-reset" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -p tcp --dport 113 -j REJECT --reject-with tcp-reset" >> $IPTABLES_CONFIG_FILTER


# ACCEPT_WHITELIST_MAKE�֐���`
# �w�肳�ꂽ�T�u�l�b�g����̃A�N�Z�X�������郆�[�U��`�`�F�C���쐬
ACCEPT_WHITELIST_MAKE(){
    for addr in `cat ./whitelist.csv`
    do
        echo "-A INPUT -s $addr -j ACCEPT" >> $IPTABLES_CONFIG_FILTER
    done
    #grep ^$1 $IP_LIST >> $CHK_IP_LIST
}



# ACCEPT_COUNTRY_MAKE�֐���`
# �w�肳�ꂽ����IP�A�h���X����̃A�N�Z�X�������郆�[�U��`�`�F�C���쐬
ACCEPT_COUNTRY_MAKE(){
    for addr in `cat /tmp/cidr.txt|grep ^$1|awk '{print $2}'`
    do
        echo "-A ACCEPT_COUNTRY -s $addr -j ACCEPT" >> $IPTABLES_CONFIG_FILTER
    done
    grep ^$1 $IP_LIST >> $CHK_IP_LIST
}

# DROP_COUNTRY_MAKE�֐���`
# �w�肳�ꂽ����IP�A�h���X����̃A�N�Z�X��j�����郆�[�U��`�`�F�C���쐬
DROP_COUNTRY_MAKE(){
    for addr in `cat /tmp/cidr.txt|grep ^$1|awk '{print $2}'`
    do
        echo "-A DROP_COUNTRY -s $addr -m limit --limit 1/s -j LOG --log-prefix \"[IPTABLES DENY_COUNTRY] : \"" >> $IPTABLES_CONFIG_FILTER
        echo "-A DROP_COUNTRY -s $addr -j DROP" >> $IPTABLES_CONFIG_FILTER
    done
    grep ^$1 $IP_LIST >> $CHK_IP_LIST
}

# IP�A�h���X���X�g�擾
IP_LIST=/tmp/cidr.txt
CHK_IP_LIST=/tmp/IPLIST
if [ ! -f $IP_LIST ]; then
    wget -q http://nami.jp/ipv4bycc/cidr.txt.gz
    gunzip -c cidr.txt.gz > $IP_LIST
    rm -f cidr.txt.gz
fi
rm -f $CHK_IP_LIST

# ���{����̃A�N�Z�X�������郆�[�U��`�`�F�C��ACCEPT_COUNTRY�쐬
ACCEPT_COUNTRY_MAKE JP
# �ȍ~,���{����̂݃A�N�Z�X�����������ꍇ��ACCEPT�̂�����ACCEPT_COUNTRY���w�肷��

# �S���x�@�{�݂ւ̍U������ʂT�J��(���{�E�A�����J������)����̃A�N�Z�X�����O���L�^���Ĕj��
# http://www.cyberpolice.go.jp/detect/observation.html���
DROP_COUNTRY_MAKE CN
DROP_COUNTRY_MAKE CA
DROP_COUNTRY_MAKE IR
DROP_COUNTRY_MAKE NL
DROP_COUNTRY_MAKE TW
echo "-A INPUT -j DROP_COUNTRY" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -j DROP_COUNTRY" >> $IPTABLES_CONFIG_FILTER

#----------------------------------------------------------#
# ���z�X�g���e��T�[�r�X�����J����ꍇ�̐ݒ�(��������)     #
#----------------------------------------------------------#
router_eq_server(){
	echo "-A INPUT -i $WAN_IF -p $PROTO --dport $PORT -j $LEVEL" >> $IPTABLES_CONFIG_FILTER
}
#----------------------------------------------------------#
# ���z�X�g���e��T�[�r�X�����J����ꍇ�̐ݒ�(�����܂�)     #
#----------------------------------------------------------#

#----------------------------------------------------------#
# ���z�X�g���e��T�[�r�X�����J����ꍇ�̐ݒ�(��������)     #
#----------------------------------------------------------#
router_ne_server(){
    echo "-A FORWARD -i $WAN_IF -p $PROTO -d $SERVER --dport $PORT -j $LEVEL" >> $IPTABLES_CONFIG_FILTER
    echo "-A PREROUTING -i $WAN_IF -p $PROTO --dport $PORT -j DNAT --to $PORT" >> $IPTABLES_CONFIG_NAT
}
#----------------------------------------------------------#
# ���z�X�g���e��T�[�r�X�����J����ꍇ�̐ݒ�(�����܂�)     #
#----------------------------------------------------------#

# ����IP�A�h���X����̃A�N�Z�X�̓��O���L�^�����ɔj��
# ������IP�A�h���X��/root/deny_ip��1�s���ƂɋL�q���Ă�������
# (/root/deny_ip���Ȃ���΂Ȃɂ����Ȃ�)
if [ -s /root/deny_ip ]; then
    for ip in `cat /root/deny_ip`
    do
        echo "-I INPUT -s $ip -j DROP" >> $IPTABLES_CONFIG_FILTER
    done
fi

# ���J�T�[�o�[�����z�X�g�̏ꍇ�̃��[���ݒ���s��
for line in `cat ./open_ports.csv`
do
        PROTO=`echo $line| cut -f1`
        PORT=`echo $line| cut -f2`
        SERVER=`echo $line| cut -f3`
        LEVEL=`echo $line| cut -f4`
        [ "$SERVER" = "$LAN_IP" ] || [ $SERVER = 127.0.0.1 ] && router_eq_server
        [ "$SERVER" != "$LAN_IP" ] && [ $SERVER != 127.0.0.1 ] && router_ne_server
done


# ��L�̃��[���Ƀ}�b�`���Ȃ������A�N�Z�X�̓��O���L�^���Ĕj��
echo "-A INPUT -j LOG --log-tcp-options --log-ip-options --log-prefix \"[IPTABLES INPUT] : \"" >> $IPTABLES_CONFIG_FILTER
echo "-A INPUT -j DROP" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -j LOG --log-tcp-options --log-ip-options --log-prefix \"[IPTABLES FORWARD] : \"" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -j DROP" >> $IPTABLES_CONFIG_FILTER

# �t�@�C�A�E�H�[���N��
echo "COMMIT" >> $IPTABLES_CONFIG_NAT
echo "COMMIT" >> $IPTABLES_CONFIG_FILTER
cat $IPTABLES_CONFIG_NAT $IPTABLES_CONFIG_FILTER > /etc/sysconfig/iptables
if [ -f /usr/libexec/iptables/iptables.init ]; then
    /usr/libexec/iptables/iptables.init restart
else
    /etc/rc.d/init.d/iptables restart
fi
rm -f $IPTABLES_CONFIG_NAT $IPTABLES_CONFIG_FILTER

# �p�P�b�g�]���J�n
sysctl -w net.ipv4.ip_forward=1 > /dev/null
sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf