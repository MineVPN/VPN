#!/bin/bash

function check_internet_connection {
    echo "Проверка доступности интернета..."
    if ping -q -c 1 -W 1 google.com >/dev/null; then
        echo ""
        echo "[*] Интернет соединение доступно."
        echo ""
    else
        echo ""
        echo "[*] Ошибка: Интернет соединение недоступно. Пожалуйста, убедитесь, что сервер подключен к сети."
        echo ""
        exit 1
    fi
}

echo ""
echo "Добро пожаловать в Настройщик Сервера с Нуля!"
echo ""

# Получаем список сетевых интерфейсов и их адресов
interfaces_and_addresses=$(ip addr show | awk '/^[0-9]+:/ {interface=$2} /inet / {split($2, parts, "/"); print interface ": " parts[1]}' | nl)

# Выводим список всех интерфейсов и их адресов с номерами
echo "Сетевые интерфейсы и их адреса:"
echo "$interfaces_and_addresses"
echo ""

# Запрашиваем у пользователя номер входного сетевого интерфейса
read -p "Введите номер входного сетевого интерфейса: " input_interface_number

# Запрашиваем у пользователя номер выходного сетевого интерфейса
read -p "Введите номер выходного сетевого интерфейса: " output_interface_number

# Получаем имена входного и выходного сетевых интерфейсов по номерам
input_interface=$(ip -o link show | awk -v num="$input_interface_number" -F': ' '$1 == num {print $2}')
output_interface=$(ip -o link show | awk -v num="$output_interface_number" -F': ' '$1 == num {print $2}')

# Выводим выбранные интерфейсы для подтверждения
echo ""
echo "Входной сетевой интерфейс: $input_interface"
echo "Выходной сетевой интерфейс: $output_interface"

# Показываем пользователю варианты настройки сетевых подключений
echo ""
echo "Выберите вариант настройки сетевых подключений:"
echo "1) Получить адрес от DHCP"
echo "2) Прописать статический адрес"
echo ""

# Проверка настроек сетевых подключений
read -p "Выберите вариант [1/2]: " choice
echo ""
sudo rm -f /etc/netplan/*


if [ "$choice" == "1" ]; then
    # Конфигурация для DHCP
    cat <<EOF > /etc/netplan/01-network-manager-all.yaml
network:
  renderer: networkd
  ethernets:
    $output_interface:
      dhcp4: false
      addresses: [10.10.10.1/24]
      nameservers: 
        addresses: [10.10.10.1]
      optional: true   
    $input_interface:
      dhcp4: true
  version: 2
EOF
elif [ "$choice" == "2" ]; then
    # Конфигурация для статического адреса
    read -p "Введите IP-адрес: " address
    read -p "Введите маску подсети: " subnet_mask
    read -p "Введите шлюз: " gateway
    read -p "Введите DNS1: " dns1
    read -p "Введите DNS2: " dns2

    cat <<EOF > /etc/netplan/01-network-manager-all.yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    $output_interface:
      dhcp4: false
      addresses: [10.10.10.1/24]
      nameservers: 
        addresses: [10.10.10.1]
      optional: true   
    $input_interface:
      dhcp4: false
      addresses: ["$address/$subnet_mask"]
      gateway4: "$gateway"
      nameservers: 
        addresses: ["$dns1", "$dns2"]
EOF
else
    echo "Неверный выбор."
    exit 1
fi


echo ""
echo "[*] Применяем настройки сети..."
echo ""
netplan apply


echo ""
echo "[*] Проверка доступа в интернет..."
echo ""
check_internet_connection


echo ""
echo "[*] Установка нужных компонентов..."
echo ""
apt-get update
apt-get upgrade -y
apt-get install -y htop net-tools mtr network-manager dnsmasq wireguard openvpn resolvconf apache2 php git
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent


echo ""
echo "[*] Разрешаеам руту подключатся по SSH..."
echo ""
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
systemctl restart sshd


echo ""
echo "[*] Настройка DHCP сервера..."
echo ""
# Путь к конфигурационному файлу dnsmasq
config_file="/etc/dnsmasq.conf"

# Добавляем необходимые параметры в конфигурационный файл dnsmasq
cat <<EOF | sudo tee -a $config_file
dhcp-authoritative
domain=link.lan
listen-address=127.0.0.1,10.10.10.1
dhcp-range=10.10.10.2,10.10.10.254,255.255.255.0,12h
server=8.8.8.8
server=8.8.4.4
cache-size=10000
EOF

sudo systemctl restart dnsmasq
sudo systemctl enable dnsmasq


echo ""
echo "[*] Создаем правила трафика..."
echo ""

sudo sed -i '/^#.*net.ipv4.ip_forward/s/^#//' /etc/sysctl.conf
sudo sysctl -p
iptables -t nat -A POSTROUTING -o tun0 -s 10.10.10.0/24 -j MASQUERADE
sudo iptables-save > /etc/iptables/rules.v4


echo ""
echo "[*] Настройка VPN протоколов..."
echo ""
sudo sed -i '/^# *AUTOSTART/s/^#//' /etc/default/openvpn


echo ""
echo "[*] Установка ЛК..."
echo ""
chmod 777 /etc/openvpn/
chmod 777 /etc/wireguard/
echo "www-data ALL=(ALL) NOPASSWD: /bin/systemctl stop openvpn*, /bin/systemctl start openvpn*" >> /etc/sudoers
echo "www-data ALL=(ALL) NOPASSWD: /bin/systemctl stop wg-quick*, /bin/systemctl start wg-quick*" >> /etc/sudoers
echo "www-data ALL=(ALL) NOPASSWD: /bin/systemctl enable wg-quick*, /bin/systemctl disable wg-quick*" >> /etc/sudoers
echo "www-data ALL=(root) NOPASSWD: /usr/bin/id" >> /etc/sudoers
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables-save > /etc/iptables/rules.v4
sudo iptables-save | sudo tee /etc/iptables/rules.v4
sudo service iptables restart
rm /var/www/html/*
sudo git clone https://github.com/MineVPN/WebVPNCabinet.git /var/www/html
echo "0 4 * * * cd /var/www/html && sudo git pull origin main" | crontab -


echo ""
echo "[*] Установка Завершена!"
echo ""
echo "Вы пожете перейти в ЛК для установки конфига"
echo "Ссылка http://10.10.10.1/ для подключения с локальной сети"
echo "Пароль от ЛК такойже как от пользователя root"
echo ""