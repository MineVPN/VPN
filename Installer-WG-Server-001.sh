#!/bin/bash

# Введення кількості клієнтів та базової назви конфігу
read -p "Введіть кількість клієнтів WireGuard: " client_count
read -p "Введіть базову назву для конфігураційних файлів клієнтів (наприклад, 'wg-client'): " base_config_name

# Визначення зовнішньої IP-адреси сервера
server_ip=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)
    if [[ -z ${server_ip} ]]; then
        server_ip=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
    fi
    read -rp "Публичный адрес IPv4: " -e -i "${server_ip}" server_ip

# Оновлення системи та встановлення WireGuard
sudo apt update
sudo apt install -y wireguard qrencode
#echo "1" > /proc/sys/net/ipv4/icmp_echo_ignore_all
echo "net.ipv4.icmp_echo_ignore_all=1" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p



# Генерація випадкового порту для WireGuard (в діапазоні 1024-65535)
wg_port=$(shuf -i 58000-65535 -n 1)

# Генерація приватного та публічного ключів для сервера
server_private_key=$(wg genkey)
server_public_key=$(echo "$server_private_key" | wg pubkey)

# Створення конфігураційного файлу сервера
echo "[Interface]
Address = 10.0.0.254/24
ListenPort = $wg_port
PrivateKey = $server_private_key
MTU = 1500
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE; echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE; echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_all
SaveConfig = true" > /etc/wireguard/wg0.conf

# Дозвіл трафіку на порт WireGuard
sudo ufw allow $wg_port/udp

# Функція для створення клієнтського конфігу
generate_client_config() {
    client_private_key=$(wg genkey)
    client_public_key=$(echo "$client_private_key" | wg pubkey)
    client_ip="10.0.0.$1/32"
    config_name="${base_config_name}$1.conf"

    # Створення конфігураційного файлу клієнта
    echo "[Interface]
Address = $client_ip
PrivateKey = $client_private_key
DNS = 8.8.8.8, 8.8.4.4, 1.1.1.1, 1.0.0.1
MTU = 1500

[Peer]
PublicKey = $server_public_key
Endpoint = $server_ip:$wg_port
AllowedIPs = 0.0.0.0/0" > "$config_name"

    # Додавання клієнта до серверного конфігу
    echo -e "\n[Peer]
PublicKey = $client_public_key
AllowedIPs = $client_ip" >> /etc/wireguard/wg0.conf
}

# Генерація конфігураційних файлів для клієнтів
for i in $(seq 1 $((client_count)))
do
    generate_client_config "$i"
done

# Запуск WireGuard сервера
sudo wg-quick up wg0

# Автоматичний запуск WireGuard при старті системи
sudo systemctl enable wg-quick@wg0

echo "WireGuard встановлено і налаштовано на порту $wg_port. Конфігураційні файли клієнтів створені з назвою $base_config_name<номер>.conf"
