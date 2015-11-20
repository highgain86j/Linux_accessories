#!/bin/bash

echo "##########<1>##########"
LAN=em1

echo "##########<2>##########"
WAN=em2

echo "##########<3>##########"
SERVER=192.168.1.254

echo "##########<4>##########"
IPADDR=`ifconfig $LAN | grep 'inet ' | sed -e 's/^.*inet //' -e 's/ .*//'`
echo $IPADDR

echo "##########<5>##########"
LOCALNET_MASK=`ifconfig $LAN | grep 'netmask ' | sed -e 's/^.*netmask //' -e 's/ .*//'`
echo $LOCALNET_MASK

echo "##########<6>##########"
LOCALNET_ADDR=$(netstat -r | grep $LAN | grep 255.255.255.0 | awk '{ print $1}')
LOCALNET=$LOCALNET_ADDR/$LOCALNET_MASK
echo $LOCALNET

echo "##########<7>##########"
sed -i '/IPTABLES_MODULES/d' /etc/sysconfig/iptables-config
modinfo ip_nat_pptp > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "IPTABLES_MODULES=\"ip_conntrack_ftp ip_nat_ftp ip_nat_pptp\"" >> /etc/sysconfig/iptables-config
else
    echo "IPTABLES_MODULES=\"ip_conntrack_ftp ip_nat_ftp\"" >> /etc/sysconfig/iptables-config
fi

echo "##########<8>##########"
sysctl -w net.ipv4.ip_forward=0 > /dev/null

echo "##########<9>##########"
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

echo "##########<10>##########"
echo "-A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu" >> $IPTABLES_CONFIG_FILTER

echo "##########<11>##########"
sysctl -w net.ipv4.tcp_syncookies=1 > /dev/null
sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
echo "net.ipv4.tcp_syncookies=1" >> /etc/sysctl.conf

echo "##########<11>##########"
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1 > /dev/null
sed -i '/net.ipv4.icmp_echo_ignore_broadcasts/d' /etc/sysctl.conf
echo "net.ipv4.icmp_echo_ignore_broadcasts=1" >> /etc/sysctl.conf

echo "##########<12>##########"
sed -i '/net.ipv4.conf.*.accept_redirects/d' /etc/sysctl.conf
for dev in `ls /proc/sys/net/ipv4/conf/`
do
    sysctl -w net.ipv4.conf.$dev.accept_redirects=0 > /dev/null
    echo "net.ipv4.conf.$dev.accept_redirects=0" >> /etc/sysctl.conf
done

echo "##########<14>##########"
sed -i '/net.ipv4.conf.*.accept_source_route/d' /etc/sysctl.conf
for dev in `ls /proc/sys/net/ipv4/conf/`
do
    sysctl -w net.ipv4.conf.$dev.accept_source_route=0 > /dev/null
    echo "net.ipv4.conf.$dev.accept_source_route=0" >> /etc/sysctl.conf
done

echo "##########<15>##########"
echo "-A LOG_FRAGMENT -j LOG --log-tcp-options --log-ip-options --log-prefix \"[IPTABLES FRAGMENT] : \"" >> $IPTABLES_CONFIG_FILTER
echo "-A LOG_FRAGMENT -j DROP" >> $IPTABLES_CONFIG_FILTER
echo "-A INPUT -f -j LOG_FRAGMENT" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -f -j LOG_FRAGMENT" >> $IPTABLES_CONFIG_FILTER

echo "##########<16>##########"
echo "-A LOG_SPOOFING -j LOG --log-tcp-options --log-ip-options --log-prefix \"[IPTABLES SPOOFING] : \"" >> $IPTABLES_CONFIG_FILTER
echo "-A LOG_SPOOFING -j DROP" >> $IPTABLES_CONFIG_FILTER
echo "-A INPUT -i $WAN -s 127.0.0.0/8    -j LOG_SPOOFING" >> $IPTABLES_CONFIG_FILTER
echo "-A INPUT -i $WAN -s 10.0.0.0/8     -j LOG_SPOOFING" >> $IPTABLES_CONFIG_FILTER
echo "-A INPUT -i $WAN -s 172.16.0.0/12  -j LOG_SPOOFING" >> $IPTABLES_CONFIG_FILTER
echo "-A INPUT -i $WAN -s 192.168.0.0/16 -j LOG_SPOOFING" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -i $WAN -s 127.0.0.0/8    -j LOG_SPOOFING" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -i $WAN -s 10.0.0.0/8     -j LOG_SPOOFING" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -i $WAN -s 172.16.0.0/12  -j LOG_SPOOFING" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -i $WAN -s 192.168.0.0/16 -j LOG_SPOOFING" >> $IPTABLES_CONFIG_FILTER

echo "##########<17>##########"
echo "-A INPUT -i $WAN -p tcp -m multiport --dports 135,137,138,139,445 -j DROP" >> $IPTABLES_CONFIG_FILTER
echo "-A INPUT -i $WAN -p udp -m multiport --dports 135,137,138,139,445 -j DROP" >> $IPTABLES_CONFIG_FILTER
echo "-A OUTPUT -o $WAN -p tcp -m multiport --sports 135,137,138,139,445 -j DROP" >> $IPTABLES_CONFIG_FILTER
echo "-A OUTPUT -o $WAN -p udp -m multiport --sports 135,137,138,139,445 -j DROP" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -i $WAN -p tcp -m multiport --dports 135,137,138,139,445 -j DROP" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -i $WAN -p udp -m multiport --dports 135,137,138,139,445 -j DROP" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -o $WAN -p tcp -m multiport --sports 135,137,138,139,445 -j DROP" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -o $WAN -p udp -m multiport --sports 135,137,138,139,445 -j DROP" >> $IPTABLES_CONFIG_FILTER

echo "##########<18>##########"
echo "-A LOG_PINGDEATH -m limit --limit 1/s --limit-burst 4 -j ACCEPT" >> $IPTABLES_CONFIG_FILTER
echo "-A LOG_PINGDEATH -j LOG --log-prefix \"[IPTABLES PINGDEATH] : \"" >> $IPTABLES_CONFIG_FILTER
echo "-A LOG_PINGDEATH -j DROP" >> $IPTABLES_CONFIG_FILTER
echo "-A INPUT -p icmp --icmp-type echo-request -j LOG_PINGDEATH" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -o ! $WAN -p icmp --icmp-type echo-request -j LOG_PINGDEATH" >> $IPTABLES_CONFIG_FILTER

echo "##########<19>##########"
echo "-A LOG_INGRESS -j LOG --log-tcp-options --log-ip-options --log-prefix \"[IPTABLES INGRESS] : \"" >> $IPTABLES_CONFIG_FILTER
echo "-A LOG_INGRESS -j DROP" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -i $LAN -s ! $LOCALNET -j LOG_INGRESS" >> $IPTABLES_CONFIG_FILTER

echo "##########<20>##########"
echo "-A INPUT -i lo -j ACCEPT" >> $IPTABLES_CONFIG_FILTER

echo "##########<21>##########"
echo "-A INPUT -i $LAN -j ACCEPT" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -i $LAN -j ACCEPT" >> $IPTABLES_CONFIG_FILTER

echo "##########<22>##########"
WAN_INF=`ls /etc/sysconfig/network-scripts/ifcfg-*|sed -e 's/^.*ifcfg-\([^ ]*\).*$/\1/p' -e d|grep ppp`
for dev in $WAN_INF
do
    echo "-A POSTROUTING -o $dev -j MASQUERADE" >> $IPTABLES_CONFIG_NAT
done

echo "##########<23>##########"
echo "-A INPUT -i $WAN -m state --state ESTABLISHED,RELATED -j ACCEPT" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -i $WAN -m state --state ESTABLISHED,RELATED -j ACCEPT" >> $IPTABLES_CONFIG_FILTER

echo "##########<24>##########"
echo "-A INPUT -p udp --sport 53 -j ACCEPT" >> $IPTABLES_CONFIG_FILTER

echo "##########<25>##########"
echo "-A INPUT -p icmp --icmp-type destination-unreachable -j ACCEPT" >> $IPTABLES_CONFIG_FILTER
echo "-A INPUT -p icmp --icmp-type source-quench -j ACCEPT" >> $IPTABLES_CONFIG_FILTER
echo "-A INPUT -p icmp --icmp-type time-exceeded -j ACCEPT" >> $IPTABLES_CONFIG_FILTER
echo "-A INPUT -p icmp --icmp-type parameter-problem -j ACCEPT" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -p icmp --icmp-type destination-unreachable -j ACCEPT" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -p icmp --icmp-type source-quench -j ACCEPT" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -p icmp --icmp-type time-exceeded -j ACCEPT" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -p icmp --icmp-type parameter-problem -j ACCEPT" >> $IPTABLES_CONFIG_FILTER

echo "##########<26>##########"
echo "-A INPUT -p tcp --dport 113 -j REJECT --reject-with tcp-reset" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -p tcp --dport 113 -j REJECT --reject-with tcp-reset" >> $IPTABLES_CONFIG_FILTER

echo "##########<27>##########"
ACCEPT_COUNTRY_MAKE(){
    for addr in `cat /tmp/cidr.txt|grep ^$1|awk '{print $2}'`
    do
        echo "-A ACCEPT_COUNTRY -s $addr -j ACCEPT" >> $IPTABLES_CONFIG_FILTER
    done
    grep ^$1 $IP_LIST >> $CHK_IP_LIST
}

echo "##########<28>##########"
DROP_COUNTRY_MAKE(){
    for addr in `cat /tmp/cidr.txt|grep ^$1|awk '{print $2}'`
    do
        echo "-A DROP_COUNTRY -s $addr -m limit --limit 1/s -j LOG --log-prefix \"[IPTABLES DENY_COUNTRY] : \"" >> $IPTABLES_CONFIG_FILTER
        echo "-A DROP_COUNTRY -s $addr -j DROP" >> $IPTABLES_CONFIG_FILTER
    done
    grep ^$1 $IP_LIST >> $CHK_IP_LIST
}

echo "##########<29>##########"
IP_LIST=/tmp/cidr.txt
CHK_IP_LIST=/tmp/IPLIST
if [ ! -f $IP_LIST ]; then
    wget -q http://nami.jp/ipv4bycc/cidr.txt.gz
    gunzip -c cidr.txt.gz > $IP_LIST
    rm -f cidr.txt.gz
fi
rm -f $CHK_IP_LIST

echo "##########<30>##########"
ACCEPT_COUNTRY_MAKE JP

echo "##########<31>##########"
DROP_COUNTRY_MAKE CN
DROP_COUNTRY_MAKE CA
DROP_COUNTRY_MAKE IR
DROP_COUNTRY_MAKE NL
DROP_COUNTRY_MAKE TW
echo "-A INPUT -j DROP_COUNTRY" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -j DROP_COUNTRY" >> $IPTABLES_CONFIG_FILTER

echo "##########<32>##########"

router_eq_server(){

    # WAN�����22�ԃ|�[�g(SSH)�ւ̃A�N�Z�X������
    # ��SSH�T�[�o�[�����J����ꍇ�̂�
    echo "-A INPUT -i $WAN -p tcp --dport 22 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG_FILTER

    # WAN�����TCP/UDP53�ԃ|�[�g(DNS)�ւ̃A�N�Z�X������
    # ��WAN����DNS�T�[�o�[���^�p����ꍇ�̂�
    echo "-A INPUT -i $WAN -p tcp --dport 53 -j ACCEPT" >> $IPTABLES_CONFIG_FILTER
    echo "-A INPUT -i $WAN -p udp --dport 53 -j ACCEPT" >> $IPTABLES_CONFIG_FILTER

    # WAN�����80�ԃ|�[�g(HTTP)�ւ̃A�N�Z�X������
    # ��Web�T�[�o�[�����J����ꍇ�̂�
    echo "-A INPUT -i $WAN -p tcp --dport 80 -j ACCEPT" >> $IPTABLES_CONFIG_FILTER

    # WAN�����443�ԃ|�[�g(HTTPS)�ւ̃A�N�Z�X������
    # ��Web�T�[�o�[�����J����ꍇ�̂�
    echo "-A INPUT -i $WAN -p tcp --dport 443 -j ACCEPT" >> $IPTABLES_CONFIG_FILTER

    # WAN�����21�ԃ|�[�g(FTP)�ւ̃A�N�Z�X������
    # ��FTP�T�[�o�[�����J����ꍇ�̂�
    echo "-A INPUT -i $WAN -p tcp --dport 21 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG_FILTER

    # WAN�����PASV�p�|�[�g(FTP-DATA)�ւ̃A�N�Z�X������
    # ��FTP�T�[�o�[�����J����ꍇ�̂�
    # ��PASV�p�|�[�g60000:60030�͓��T�C�g�̐ݒ��
    echo "-A INPUT -i $WAN -p tcp --dport 60000:60030 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG_FILTER

    # WAN�����25�ԃ|�[�g(SMTP)�ւ̃A�N�Z�X������
    # ��SMTP�T�[�o�[�����J����ꍇ�̂�
    echo "-A INPUT -i $WAN -p tcp --dport 25 -j ACCEPT" >> $IPTABLES_CONFIG_FILTER

    # WAN�����465�ԃ|�[�g(SMTPS)�ւ̃A�N�Z�X������
    # ��SMTPS�T�[�o�[�����J����ꍇ�̂�
    echo "-A INPUT -i $WAN -p tcp --dport 465 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG_FILTER

    # WAN�����110�ԃ|�[�g(POP3)�ւ̃A�N�Z�X������
    # ��POP3�T�[�o�[�����J����ꍇ�̂�
    echo "-A INPUT -i $WAN -p tcp --dport 110 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG_FILTER

    # WAN�����995�ԃ|�[�g(POP3S)�ւ̃A�N�Z�X������
    # ��POP3S�T�[�o�[�����J����ꍇ�̂�
    echo "-A INPUT -i $WAN -p tcp --dport 995 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG_FILTER

    # WAN�����143�ԃ|�[�g(IMAP)�ւ̃A�N�Z�X������
    # ��IMAP�T�[�o�[�����J����ꍇ�̂�
    echo "-A INPUT -i $WAN -p tcp --dport 143 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG_FILTER

    # WAN�����993�ԃ|�[�g(IMAPS)�ւ̃A�N�Z�X������
    # ��IMAPS�T�[�o�[�����J����ꍇ�̂�
    echo "-A INPUT -i $WAN -p tcp --dport 993 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG_FILTER

}

echo "##########<33>##########"

router_ne_server(){

    # WAN����̌��J�T�[�o�[��22�ԃ|�[�g(SSH)�ւ̃A�N�Z�X������&�]��
    # ��SSH�T�[�o�[�����J����ꍇ�̂�
    echo "-A FORWARD -i $WAN -p tcp -d $SERVER --dport 22 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG_FILTER
    echo "-A PREROUTING -i $WAN -p tcp --dport 22 -j DNAT --to $SERVER" >> $IPTABLES_CONFIG_NAT

    # WAN����̌��J�T�[�o�[��TCP/UDP53�ԃ|�[�g(DNS)�ւ̃A�N�Z�X������&�]��
    # ��WAN����DNS�T�[�o�[���^�p����ꍇ�̂�
    echo "-A FORWARD -i $WAN -p tcp -d $SERVER --dport 53 -j ACCEPT" >> $IPTABLES_CONFIG_FILTER
    echo "-A PREROUTING -i $WAN -p tcp --dport 53 -j DNAT --to $SERVER" >> $IPTABLES_CONFIG_NAT
    echo "-A FORWARD -i $WAN -p udp -d $SERVER --dport 53 -j ACCEPT" >> $IPTABLES_CONFIG_FILTER
    echo "-A PREROUTING -i $WAN -p udp --dport 53 -j DNAT --to $SERVER" >> $IPTABLES_CONFIG_NAT

    # WAN����̌��J�T�[�o�[��80�ԃ|�[�g(HTTP)�ւ̃A�N�Z�X������&�]��
    # ��Web�T�[�o�[�����J����ꍇ�̂�
    echo "-A FORWARD -i $WAN -p tcp -d $SERVER --dport 80 -j ACCEPT" >> $IPTABLES_CONFIG_FILTER
    echo "-A PREROUTING -i $WAN -p tcp --dport 80 -j DNAT --to $SERVER" >> $IPTABLES_CONFIG_NAT

    # WAN����̌��J�T�[�o�[��443�ԃ|�[�g(HTTPS)�ւ̃A�N�Z�X������&�]��
    # ��Web�T�[�o�[�����J����ꍇ�̂�
    echo "-A FORWARD -i $WAN -p tcp -d $SERVER --dport 443 -j ACCEPT" >> $IPTABLES_CONFIG_FILTER
    echo "-A PREROUTING -i $WAN -p tcp --dport 443 -j DNAT --to $SERVER" >> $IPTABLES_CONFIG_NAT

    # WAN����̌��J�T�[�o�[��21�ԃ|�[�g(FTP)�ւ̃A�N�Z�X������&�]��
    # ��FTP�T�[�o�[�����J����ꍇ�̂�
    echo "-A FORWARD -i $WAN -p tcp -d $SERVER --dport 21 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG_FILTER
    echo "-A PREROUTING -i $WAN -p tcp --dport 21 -j DNAT --to $SERVER" >> $IPTABLES_CONFIG_NAT

    # WAN����̌��J�T�[�o�[��PASV�p�|�[�g(FTP-DATA)�ւ̃A�N�Z�X������&�]��
    # ��FTP�T�[�o�[�����J����ꍇ�̂�
    # ��PASV�p�|�[�g60000:60030�͓��T�C�g�̐ݒ��
    echo "-A FORWARD -i $WAN -p tcp -d $SERVER --dport 60000:60030 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG_FILTER
    echo "-A PREROUTING -i $WAN -p tcp --dport 60000:60030 -j DNAT --to $SERVER" >> $IPTABLES_CONFIG_NAT

    # WAN����̌��J�T�[�o�[��25�ԃ|�[�g(SMTP)�ւ̃A�N�Z�X������&�]��
    # ��SMTP�T�[�o�[�����J����ꍇ�̂�
    echo "-A FORWARD -i $WAN -p tcp -d $SERVER --dport 25 -j ACCEPT" >> $IPTABLES_CONFIG_FILTER
    echo "-A PREROUTING -i $WAN -p tcp --dport 25 -j DNAT --to $SERVER" >> $IPTABLES_CONFIG_NAT

    # WAN����̌��J�T�[�o�[��465�ԃ|�[�g(SMTPS)�ւ̃A�N�Z�X������&�]��
    # ��SMTPS�T�[�o�[�����J����ꍇ�̂�
    echo "-A FORWARD -i $WAN -p tcp -d $SERVER --dport 465 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG_FILTER
    echo "-A PREROUTING -i $WAN -p tcp --dport 465 -j DNAT --to $SERVER" >> $IPTABLES_CONFIG_NAT

    # WAN����̌��J�T�[�o�[��110�ԃ|�[�g(POP3)�ւ̃A�N�Z�X������&�]��
    # ��POP3�T�[�o�[�����J����ꍇ�̂�
    echo "-A FORWARD -i $WAN -p tcp -d $SERVER --dport 110 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG_FILTER
    echo "-A PREROUTING -i $WAN -p tcp --dport 110 -j DNAT --to $SERVER" >> $IPTABLES_CONFIG_NAT

    # WAN����̌��J�T�[�o�[��995�ԃ|�[�g(POP3S)�ւ̃A�N�Z�X������&�]��
    # ��POP3S�T�[�o�[�����J����ꍇ�̂�
    echo "-A FORWARD -i $WAN -p tcp -d $SERVER --dport 995 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG_FILTER
    echo "-A PREROUTING -i $WAN -p tcp --dport 995 -j DNAT --to $SERVER" >> $IPTABLES_CONFIG_NAT

    # WAN����̌��J�T�[�o�[��143�ԃ|�[�g(IMAP)�ւ̃A�N�Z�X������&�]��
    # ��IMAP�T�[�o�[�����J����ꍇ�̂�
    echo "-A FORWARD -i $WAN -p tcp -d $SERVER --dport 143 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG_FILTER
    echo "-A PREROUTING -i $WAN -p tcp --dport 143 -j DNAT --to $SERVER" >> $IPTABLES_CONFIG_NAT

    # WAN����̌��J�T�[�o�[��993�ԃ|�[�g(IMAPS)�ւ̃A�N�Z�X������&�]��
    # ��IMAPS�T�[�o�[�����J����ꍇ�̂�
    echo "-A FORWARD -i $WAN -p tcp -d $SERVER --dport 993 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG_FILTER
    echo "-A PREROUTING -i $WAN -p tcp --dport 993 -j DNAT --to $SERVER" >> $IPTABLES_CONFIG_NAT

    # WAN����̌��J�T�[�o�[��UDP1194�ԃ|�[�g(OpenVPN)�ւ̃A�N�Z�X������&�]��
    # ��OpenVPN�T�[�o�[�����J����ꍇ�̂�
    echo "-A FORWARD -i $WAN -p udp -d $SERVER --dport 1194 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG_FILTER
    echo "-A PREROUTING -i $WAN -p udp --dport 1194 -j DNAT --to $SERVER" >> $IPTABLES_CONFIG_NAT



}

echo "##########<34>##########"
if [ -s /root/deny_ip ]; then
    for ip in `cat /root/deny_ip`
    do
        echo "-I INPUT -s $ip -j DROP" >> $IPTABLES_CONFIG_FILTER
    done
fi

echo "##########<35>##########"
[ "$SERVER" = "$IPADDR" ] || [ $SERVER = 127.0.0.1 ] && router_eq_server

echo "##########<36>##########"
[ "$SERVER" != "$IPADDR" ] && [ $SERVER != 127.0.0.1 ] && router_ne_server


echo "##########<37>##########"
echo "-A INPUT -j LOG --log-tcp-options --log-ip-options --log-prefix \"[IPTABLES INPUT] : \"" >> $IPTABLES_CONFIG_FILTER
echo "-A INPUT -j DROP" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -j LOG --log-tcp-options --log-ip-options --log-prefix \"[IPTABLES FORWARD] : \"" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -j DROP" >> $IPTABLES_CONFIG_FILTER

echo "##########<38>##########"
echo "COMMIT" >> $IPTABLES_CONFIG_NAT
echo "COMMIT" >> $IPTABLES_CONFIG_FILTER
cat $IPTABLES_CONFIG_NAT $IPTABLES_CONFIG_FILTER > /etc/sysconfig/iptables
if [ -f /usr/libexec/iptables/iptables.init ]; then
    /usr/libexec/iptables/iptables.init restart
else
    /etc/rc.d/init.d/iptables restart
fi
rm -f $IPTABLES_CONFIG_NAT $IPTABLES_CONFIG_FILTER

echo "##########<39>##########"
sysctl -w net.ipv4.ip_forward=1 > /dev/null
sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf


rm -rf $IPTABLES_CONFIG_NAT
rm -rf $IPTABLES_CONFIG_FILTER