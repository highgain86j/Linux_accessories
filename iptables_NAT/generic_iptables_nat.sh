#!/bin/bash

# thanks to http://centossrv.com/linux-router.shtml
# This script assumes;
# Network address on LAN:	192.168.1.0
# Subnet mask on LAN:		255.255.255.0

LOCALNET_ADDR=192.168.1.0
LOCALNET_MASK=255.255.255.0
LOCALNET=$LOCALNET_ADDR/$LOCALNET_MASK

#---------------------------------------#
# 設定開始                              #
#---------------------------------------#

# WANインタフェース名定義
WAN_IF=`route -4 | grep default | sed 's/[\t ]\+/\t/g' | cut -f8`

# LANインタフェース名定義
LAN_IF=`route -4 | grep $LOCALNET_ADDR | sed 's/[\t ]\+/\t/g' | cut -f8`

# 公開サーバープライベートIPアドレス定義
# SERVER=192.168.1.3

#---------------------------------------#
# 設定終了                              #
#---------------------------------------#

# 自ホストプライベートIPアドレス取得
LAN_IP=`ifconfig $LAN_IF | grep 'inet ' | sed -e 's/^.*inet //' -e 's/ .*//'`

# 自ホストグローバルIPアドレス取得
WAN_IP=`ifconfig $WAN_IF | grep 'inet ' | sed -e 's/^.*inet //' -e 's/ .*//'`


#---------------------------------------#
# 環境確認                              #
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


# 読み込み対象モジュール追加
sed -i '/IPTABLES_MODULES/d' /etc/sysconfig/iptables-config
modinfo ip_nat_pptp > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "IPTABLES_MODULES=\"ip_conntrack_ftp ip_nat_ftp ip_nat_pptp\"" >> /etc/sysconfig/iptables-config
else
    echo "IPTABLES_MODULES=\"ip_conntrack_ftp ip_nat_ftp\"" >> /etc/sysconfig/iptables-config
fi

# パケット転送停止
# ※ルール設定中のパケット通過防止
sysctl -w net.ipv4.ip_forward=0 > /dev/null

# デフォルトルール(以降のルールにマッチしなかった場合に適用するルール)設定
IPTABLES_CONFIG_NAT=`mktemp`
IPTABLES_CONFIG_FILTER=`mktemp`
echo "*nat" >> $IPTABLES_CONFIG_NAT
echo ":PREROUTING ACCEPT [0:0]" >> $IPTABLES_CONFIG_NAT
echo ":POSTROUTING ACCEPT [0:0]" >> $IPTABLES_CONFIG_NAT
echo ":OUTPUT ACCEPT [0:0]" >> $IPTABLES_CONFIG_NAT
echo "*filter" >> $IPTABLES_CONFIG_FILTER
echo ":INPUT DROP [0:0]" >> $IPTABLES_CONFIG_FILTER       # 受信はすべて破棄
echo ":FORWARD DROP [0:0]" >> $IPTABLES_CONFIG_FILTER     # 通過はすべて破棄
echo ":OUTPUT ACCEPT [0:0]" >> $IPTABLES_CONFIG_FILTER    # 送信はすべて許可
echo ":ACCEPT_COUNTRY - [0:0]" >> $IPTABLES_CONFIG_FILTER # 指定した国からのアクセスを許可
echo ":DROP_COUNTRY - [0:0]" >> $IPTABLES_CONFIG_FILTER   # 指定した国からのアクセスを破棄
echo ":LOG_FRAGMENT - [0:0]" >> $IPTABLES_CONFIG_FILTER   # フラグメント化されたパケットはログを記録して破棄
echo ":LOG_INGRESS - [0:0]" >> $IPTABLES_CONFIG_FILTER    # 送信元IPアドレスがLANネットワーク範囲外のアクセスはログを記録して破棄
echo ":LOG_PINGDEATH - [0:0]" >> $IPTABLES_CONFIG_FILTER  # Ping of Death攻撃はログを記録して破棄
echo ":LOG_SPOOFING - [0:0]" >> $IPTABLES_CONFIG_FILTER   # WANからの送信元がプライベートIPアドレスのパケットはログを記録して破棄

# パスMTU問題対処
echo "-A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu" >> $IPTABLES_CONFIG_FILTER

# SYN Cookiesを有効にする
# ※TCP SYN Flood攻撃対策
sysctl -w net.ipv4.tcp_syncookies=1 > /dev/null
sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
echo "net.ipv4.tcp_syncookies=1" >> /etc/sysctl.conf

# ブロードキャストアドレス宛pingには応答しない
# ※Smurf攻撃対策
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1 > /dev/null
sed -i '/net.ipv4.icmp_echo_ignore_broadcasts/d' /etc/sysctl.conf
echo "net.ipv4.icmp_echo_ignore_broadcasts=1" >> /etc/sysctl.conf

# ICMP Redirectパケットは拒否
sed -i '/net.ipv4.conf.*.accept_redirects/d' /etc/sysctl.conf
for dev in `ls /proc/sys/net/ipv4/conf/`
do
    sysctl -w net.ipv4.conf.$dev.accept_redirects=0 > /dev/null
    echo "net.ipv4.conf.$dev.accept_redirects=0" >> /etc/sysctl.conf
done

# Source Routedパケットは拒否
sed -i '/net.ipv4.conf.*.accept_source_route/d' /etc/sysctl.conf
for dev in `ls /proc/sys/net/ipv4/conf/`
do
    sysctl -w net.ipv4.conf.$dev.accept_source_route=0 > /dev/null
    echo "net.ipv4.conf.$dev.accept_source_route=0" >> /etc/sysctl.conf
done

# フラグメント化されたパケットはログを記録して破棄
echo "-A LOG_FRAGMENT -j LOG --log-tcp-options --log-ip-options --log-prefix \"[IPTABLES FRAGMENT] : \"" >> $IPTABLES_CONFIG_FILTER
echo "-A LOG_FRAGMENT -j DROP" >> $IPTABLES_CONFIG_FILTER
echo "-A INPUT -f -j LOG_FRAGMENT" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -f -j LOG_FRAGMENT" >> $IPTABLES_CONFIG_FILTER

# WANからの送信元がプライベートIPアドレスのパケットはログを記録して破棄
# ※IP spoofing攻撃対策
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

# WANとのNetBIOS関連のアクセスはログを記録せずに破棄
echo "-A INPUT -i $WAN_IF -p tcp -m multiport --dports 135,137,138,139,445 -j DROP" >> $IPTABLES_CONFIG_FILTER
echo "-A INPUT -i $WAN_IF -p udp -m multiport --dports 135,137,138,139,445 -j DROP" >> $IPTABLES_CONFIG_FILTER
echo "-A OUTPUT -o $WAN_IF -p tcp -m multiport --sports 135,137,138,139,445 -j DROP" >> $IPTABLES_CONFIG_FILTER
echo "-A OUTPUT -o $WAN_IF -p udp -m multiport --sports 135,137,138,139,445 -j DROP" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -i $WAN_IF -p tcp -m multiport --dports 135,137,138,139,445 -j DROP" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -i $WAN_IF -p udp -m multiport --dports 135,137,138,139,445 -j DROP" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -o $WAN_IF -p tcp -m multiport --sports 135,137,138,139,445 -j DROP" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -o $WAN_IF -p udp -m multiport --sports 135,137,138,139,445 -j DROP" >> $IPTABLES_CONFIG_FILTER

# 1秒間に4回を超えるpingはログを記録して破棄
echo "-A LOG_PINGDEATH -m limit --limit 1/s --limit-burst 4 -j ACCEPT" >> $IPTABLES_CONFIG_FILTER
echo "-A LOG_PINGDEATH -j LOG --log-prefix \"[IPTABLES PINGDEATH] : \"" >> $IPTABLES_CONFIG_FILTER
echo "-A LOG_PINGDEATH -j DROP" >> $IPTABLES_CONFIG_FILTER
echo "-A INPUT -p icmp --icmp-type echo-request -j LOG_PINGDEATH" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -o ! $WAN_IF -p icmp --icmp-type echo-request -j LOG_PINGDEATH" >> $IPTABLES_CONFIG_FILTER

# 送信元IPアドレスがLANネットワーク範囲外のアクセスはログを記録して破棄
# ※Ingress対策
echo "-A LOG_INGRESS -j LOG --log-tcp-options --log-ip-options --log-prefix \"[IPTABLES INGRESS] : \"" >> $IPTABLES_CONFIG_FILTER
echo "-A LOG_INGRESS -j DROP" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -i $LAN_IF -s ! $LOCALNET -j LOG_INGRESS" >> $IPTABLES_CONFIG_FILTER

# 自ホストからのアクセスをすべて許可
echo "-A INPUT -i lo -j ACCEPT" >> $IPTABLES_CONFIG_FILTER

# ACCEPT_WHITELIST_MAKE関数定義
# 指定されたサブネットからのアクセスを許可するユーザ定義チェイン作成
ACCEPT_WHITELIST_MAKE

# LANからのアクセスをすべて許可
echo "-A INPUT -i $LAN_IF -j ACCEPT" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -i $LAN_IF -j ACCEPT" >> $IPTABLES_CONFIG_FILTER

## LANからのインターネットへの同時接続を可能にする
## ※IP masquerade(NAPT) 
#WAN_INF=`ls /etc/sysconfig/network-scripts/ifcfg-*|sed -e 's/^.*ifcfg-\([^ ]*\).*$/\1/p' -e d|grep ppp`
#for dev in $WAN_INF
#do
#    echo "-A POSTROUTING -o $dev -j MASQUERADE" >> $IPTABLES_CONFIG_NAT
#         
#done

echo "-A POSTROUTING -s $LOCALNET -o $WAN_IF -j MASQUERADE" >> $IPTABLES_CONFIG_NAT

# LANから行ったアクセスに対するWANからの返答アクセスを許可
echo "-A INPUT -i $WAN_IF -m state --state ESTABLISHED,RELATED -j ACCEPT" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -i $WAN_IF -m state --state ESTABLISHED,RELATED -j ACCEPT" >> $IPTABLES_CONFIG_FILTER

# DNS応答アクセスを許可
echo "-A INPUT -p udp --sport 53 -j ACCEPT" >> $IPTABLES_CONFIG_FILTER

# WANからの必須ICMPパケットを許可
echo "-A INPUT -p icmp --icmp-type destination-unreachable -j ACCEPT" >> $IPTABLES_CONFIG_FILTER
echo "-A INPUT -p icmp --icmp-type source-quench -j ACCEPT" >> $IPTABLES_CONFIG_FILTER
echo "-A INPUT -p icmp --icmp-type time-exceeded -j ACCEPT" >> $IPTABLES_CONFIG_FILTER
echo "-A INPUT -p icmp --icmp-type parameter-problem -j ACCEPT" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -p icmp --icmp-type destination-unreachable -j ACCEPT" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -p icmp --icmp-type source-quench -j ACCEPT" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -p icmp --icmp-type time-exceeded -j ACCEPT" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -p icmp --icmp-type parameter-problem -j ACCEPT" >> $IPTABLES_CONFIG_FILTER

# 113番ポート(IDENT)へのアクセスには拒否応答
# ※メールサーバ等のレスポンス低下防止
echo "-A INPUT -p tcp --dport 113 -j REJECT --reject-with tcp-reset" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -p tcp --dport 113 -j REJECT --reject-with tcp-reset" >> $IPTABLES_CONFIG_FILTER


# ACCEPT_WHITELIST_MAKE関数定義
# 指定されたサブネットからのアクセスを許可するユーザ定義チェイン作成
ACCEPT_WHITELIST_MAKE(){
    for addr in `cat ./whitelist.csv`
    do
        echo "-A INPUT -s $addr -j ACCEPT" >> $IPTABLES_CONFIG_FILTER
    done
    #grep ^$1 $IP_LIST >> $CHK_IP_LIST
}



# ACCEPT_COUNTRY_MAKE関数定義
# 指定された国のIPアドレスからのアクセスを許可するユーザ定義チェイン作成
ACCEPT_COUNTRY_MAKE(){
    for addr in `cat /tmp/cidr.txt|grep ^$1|awk '{print $2}'`
    do
        echo "-A ACCEPT_COUNTRY -s $addr -j ACCEPT" >> $IPTABLES_CONFIG_FILTER
    done
    grep ^$1 $IP_LIST >> $CHK_IP_LIST
}

# DROP_COUNTRY_MAKE関数定義
# 指定された国のIPアドレスからのアクセスを破棄するユーザ定義チェイン作成
DROP_COUNTRY_MAKE(){
    for addr in `cat /tmp/cidr.txt|grep ^$1|awk '{print $2}'`
    do
        echo "-A DROP_COUNTRY -s $addr -m limit --limit 1/s -j LOG --log-prefix \"[IPTABLES DENY_COUNTRY] : \"" >> $IPTABLES_CONFIG_FILTER
        echo "-A DROP_COUNTRY -s $addr -j DROP" >> $IPTABLES_CONFIG_FILTER
    done
    grep ^$1 $IP_LIST >> $CHK_IP_LIST
}

# IPアドレスリスト取得
IP_LIST=/tmp/cidr.txt
CHK_IP_LIST=/tmp/IPLIST
if [ ! -f $IP_LIST ]; then
    wget -q http://nami.jp/ipv4bycc/cidr.txt.gz
    gunzip -c cidr.txt.gz > $IP_LIST
    rm -f cidr.txt.gz
fi
rm -f $CHK_IP_LIST

# 日本からのアクセスを許可するユーザ定義チェインACCEPT_COUNTRY作成
ACCEPT_COUNTRY_MAKE JP
# 以降,日本からのみアクセスを許可したい場合はACCEPTのかわりにACCEPT_COUNTRYを指定する

# 全国警察施設への攻撃元上位５カ国(日本・アメリカを除く)からのアクセスをログを記録して破棄
# http://www.cyberpolice.go.jp/detect/observation.htmlより
DROP_COUNTRY_MAKE CN
DROP_COUNTRY_MAKE CA
DROP_COUNTRY_MAKE IR
DROP_COUNTRY_MAKE NL
DROP_COUNTRY_MAKE TW
echo "-A INPUT -j DROP_COUNTRY" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -j DROP_COUNTRY" >> $IPTABLES_CONFIG_FILTER

#----------------------------------------------------------#
# 自ホストが各種サービスを公開する場合の設定(ここから)     #
#----------------------------------------------------------#
router_eq_server(){
	echo "-A INPUT -i $WAN_IF -p $PROTO --dport $PORT -j $LEVEL" >> $IPTABLES_CONFIG_FILTER
}
#----------------------------------------------------------#
# 自ホストが各種サービスを公開する場合の設定(ここまで)     #
#----------------------------------------------------------#

#----------------------------------------------------------#
# 他ホストが各種サービスを公開する場合の設定(ここから)     #
#----------------------------------------------------------#
router_ne_server(){
    echo "-A FORWARD -i $WAN_IF -p $PROTO -d $SERVER --dport $PORT -j $LEVEL" >> $IPTABLES_CONFIG_FILTER
    echo "-A PREROUTING -i $WAN_IF -p $PROTO --dport $PORT -j DNAT --to $PORT" >> $IPTABLES_CONFIG_NAT
}
#----------------------------------------------------------#
# 他ホストが各種サービスを公開する場合の設定(ここまで)     #
#----------------------------------------------------------#

# 拒否IPアドレスからのアクセスはログを記録せずに破棄
# ※拒否IPアドレスは/root/deny_ipに1行ごとに記述しておくこと
# (/root/deny_ipがなければなにもしない)
if [ -s /root/deny_ip ]; then
    for ip in `cat /root/deny_ip`
    do
        echo "-I INPUT -s $ip -j DROP" >> $IPTABLES_CONFIG_FILTER
    done
fi

# 公開サーバーが自ホストの場合のルール設定を行う
for line in `cat ./open_ports.csv`
do
        PROTO=`echo $line| cut -f1`
        PORT=`echo $line| cut -f2`
        SERVER=`echo $line| cut -f3`
        LEVEL=`echo $line| cut -f4`
        [ "$SERVER" = "$LAN_IP" ] || [ $SERVER = 127.0.0.1 ] && router_eq_server
        [ "$SERVER" != "$LAN_IP" ] && [ $SERVER != 127.0.0.1 ] && router_ne_server
done


# 上記のルールにマッチしなかったアクセスはログを記録して破棄
echo "-A INPUT -j LOG --log-tcp-options --log-ip-options --log-prefix \"[IPTABLES INPUT] : \"" >> $IPTABLES_CONFIG_FILTER
echo "-A INPUT -j DROP" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -j LOG --log-tcp-options --log-ip-options --log-prefix \"[IPTABLES FORWARD] : \"" >> $IPTABLES_CONFIG_FILTER
echo "-A FORWARD -j DROP" >> $IPTABLES_CONFIG_FILTER

# ファイアウォール起動
echo "COMMIT" >> $IPTABLES_CONFIG_NAT
echo "COMMIT" >> $IPTABLES_CONFIG_FILTER
cat $IPTABLES_CONFIG_NAT $IPTABLES_CONFIG_FILTER > /etc/sysconfig/iptables
if [ -f /usr/libexec/iptables/iptables.init ]; then
    /usr/libexec/iptables/iptables.init restart
else
    /etc/rc.d/init.d/iptables restart
fi
rm -f $IPTABLES_CONFIG_NAT $IPTABLES_CONFIG_FILTER

# パケット転送開始
sysctl -w net.ipv4.ip_forward=1 > /dev/null
sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf