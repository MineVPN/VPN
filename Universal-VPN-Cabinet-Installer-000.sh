echo ""
echo "[*] Установка ЛК..."
echo ""
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y net-tools network-manager wireguard openvpn resolvconf apache2 php git iptables-persistent
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
sudo git clone https://github.com/MineVPN/UniversalWebVPNCabinet.git /var/www/html
echo "0 4 * * * /bin/bash /var/www/html/update.sh" | sudo crontab -


echo ""
echo "[*] Установка Завершена!"
echo ""
echo "Вы можете перейти в ЛК для установки конфига"
echo "По локальному адресу сервера http://192.168..."
echo "Пароль от ЛК такойже как от пользователя root"
echo ""
