#!/bin/bash

function getServerIP() {
    IP=$(ip -4 addr show | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)
    echo "$IP"
}


# Определение сетевого интерфейса
NETWORK_INTERFACE=$(ip route | awk '/default/ { print $5 }')

# Удаление предыдущих настроек
sudo systemctl stop strongswan-starter xl2tpd
sudo apt remove --purge -y strongswan xl2tpd iptables-persistent
sudo rm -rf /etc/ipsec.conf /etc/ipsec.secrets /etc/xl2tpd /etc/sysctl.conf /etc/ppp
systemctl disable --now systemd-journald.service
systemctl disable --now syslog.socket rsyslog.service
log_files=("/var/log/auth.log" "/var/log/syslog")

for log_file in "${log_files[@]}"
do
    if [ -f "$log_file" ]; then
        echo "Файл $log_file существует. Удаление..."
        rm "$log_file"
        echo "Файл $log_file успешно удален."
    else
        echo "Файл $log_file не существует."
    fi
done

# Проверка и удаление файлов, если они существуют
[ -e /etc/ppp/options.xl2tpd ] && sudo rm /etc/ppp/options.xl2tpd
[ -e /etc/ppp/chap-secrets ] && sudo rm /etc/ppp/chap-secrets

# Создание необходимых директорий
sudo mkdir -p /etc/ppp

# Установка необходимых пакетов без интерактивных запросов
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y strongswan xl2tpd iptables-persistent

# Включение IP Forwarding
echo "net.ipv4.ip_forward = 1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Настройка IPsec
cat <<EOF | sudo tee /etc/ipsec.conf > /dev/null
config setup
    charondebug="ike 2, knl 2, cfg 2, net 2, esp 2, dmn 2, 0"
    uniqueids=yes
    strictcrlpolicy=no

conn L2TP-PSK
    authby=secret
    auto=add
    keyingtries=3
    dpddelay=30
    dpdtimeout=120
    dpdaction=clear
    rekey=yes
    ikelifetime=8h
    keylife=1h
    type=transport
    left=%any
    leftprotoport=17/1701
    right=%any
    rightprotoport=17/1701
    forceencaps=yes
EOF

# Генерация случайного секретного ключа IPsec
IPSEC_SECRET_KEY=$(openssl rand -hex 16)
echo ": PSK \"$IPSEC_SECRET_KEY\"" | sudo tee /etc/ipsec.secrets > /dev/null

# Настройка L2TP
sudo mkdir -p /etc/xl2tpd
cat <<EOF | sudo tee /etc/xl2tpd/xl2tpd.conf > /dev/null
[global]
ipsec saref = yes

[lns default]
ip range = 192.168.42.10-192.168.42.50
local ip = 192.168.42.1
refuse chap = yes
refuse pap = yes
require authentication = yes
name = l2tpd
ppp debug = yes
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOF

# Создание файла опций для PPP
sudo touch /etc/ppp/options.xl2tpd
cat <<EOF | sudo tee /etc/ppp/options.xl2tpd > /dev/null
require-mschap-v2
ms-dns 8.8.8.8
ms-dns 8.8.4.4
asyncmap 0
auth
crtscts
lock
hide-password
modem
debug
name l2tpd
proxyarp
lcp-echo-interval 30
lcp-echo-failure 4
defaultroute
EOF

sudo mkdir -p /etc/iptables

# Настройка правил iptables для маршрутизации и NAT
sudo iptables -t nat -A POSTROUTING -o $NETWORK_INTERFACE -j MASQUERADE
sudo iptables -A FORWARD -m policy --pol ipsec --dir in -s 192.168.42.0/24 -o $NETWORK_INTERFACE -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
sudo iptables -A FORWARD -s 192.168.42.0/24 -o $NETWORK_INTERFACE -j ACCEPT
sudo iptables -A FORWARD -d 192.168.42.0/24 -m policy --pol ipsec --dir out -i $NETWORK_INTERFACE -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
sudo iptables -A FORWARD -d 192.168.42.0/24 -i $NETWORK_INTERFACE -j ACCEPT
sudo iptables-save > /etc/iptables/rules.v4

echo " "
echo " "
echo "         L2TP-сервер был успешно настроен!"
echo " "
echo " "
# Вывод информации
OUTPUT_FILE="/root/l2tp.txt"
{
    echo "==================================================="
    echo " IP: $(getServerIP)"
    echo " IPsec ключ: $IPSEC_SECRET_KEY"
    echo "==================================================="
} | sudo tee $OUTPUT_FILE

# Создание трех пользователей L2TP
sudo touch /etc/ppp/chap-secrets
USERS=("mine1" "mine2" "mine3")
for USER in "${USERS[@]}"; do
    PASSWORD=$(openssl rand -base64 12)
    echo "$USER l2tpd $PASSWORD *" | sudo tee -a /etc/ppp/chap-secrets > /dev/null
    echo " Пользователь: $USER Пароль: $PASSWORD " | sudo tee -a $OUTPUT_FILE
done

{
    echo "==================================================="
    echo " "
    echo " "
} | sudo tee -a $OUTPUT_FILE

# Перезапуск сервисов
sudo systemctl restart strongswan-starter xl2tpd

echo "Данные для подключения сохранены в $OUTPUT_FILE"
echo " "
echo " "
