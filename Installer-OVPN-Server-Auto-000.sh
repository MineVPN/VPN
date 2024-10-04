#!/bin/bash

# Скрипт установки OpenVPN с проверками успешности установки и генерации ключей.

# Максимальное количество попыток установки и генерации ключей
MAX_INSTALL_ATTEMPTS=3
MAX_KEY_GENERATION_ATTEMPTS=3

# Лог-файл для записи действий и ошибок
LOG_FILE="/var/log/openvpn_install.log"

# Перенаправление вывода и ошибок в лог-файл
exec > >(tee -a "$LOG_FILE") 2>&1

# Функция проверки запуска от root
function isRoot() {
    if [ "$EUID" -ne 0 ]; then
        echo "Извините, вам нужно запустить это как root."
        exit 1
    fi
}

# Функция проверки доступности TUN
function tunAvailable() {
    if [ ! -e /dev/net/tun ]; then
        echo "TUN не доступен. Пожалуйста, убедитесь, что модуль TUN загружен."
        exit 1
    fi
}

# Функция определения операционной системы
function checkOS() {
    if [[ -e /etc/debian_version ]]; then
        OS="debian"
        source /etc/os-release

        if [[ $ID == "debian" || $ID == "raspbian" ]]; then
            if [[ $VERSION_ID < "9" ]]; then
                echo "⚠️ Ваша версия Debian не поддерживается."
                echo "Однако, если вы используете Debian >= 9 или нестабильную/тестирующую версию, вы можете продолжить на свой страх и риск."
                echo ""
                CONTINUE="y"
            fi
        elif [[ $ID == "ubuntu" ]]; then
            OS="ubuntu"
            MAJOR_UBUNTU_VERSION=$(echo "$VERSION_ID" | cut -d '.' -f1)
            if [[ $MAJOR_UBUNTU_VERSION -lt 16 ]]; then
                echo "⚠️ Ваша версия Ubuntu не поддерживается."
                echo "Однако, если вы используете Ubuntu >= 16.04 или бета-версию, вы можете продолжить на свой страх и риск."
                echo ""
                CONTINUE="y"
            fi
        fi
    elif [[ -e /etc/system-release ]]; then
        source /etc/os-release
        if [[ $ID == "fedora" || $ID_LIKE == "fedora" ]]; then
            OS="fedora"
        fi
        if [[ $ID == "centos" || $ID == "rocky" || $ID == "almalinux" ]]; then
            OS="centos"
            if [[ ! $VERSION_ID =~ ^(7|8)$ ]]; then
                echo "⚠️ Ваша версия CentOS не поддерживается."
                echo "Скрипт поддерживает только CentOS 7 и CentOS 8."
                exit 1
            fi
        fi
        if [[ $ID == "ol" ]]; then
            OS="oracle"
            if [[ $VERSION_ID != "8" ]]; then
                echo "Ваша версия Oracle Linux не поддерживается."
                echo "Скрипт поддерживает только Oracle Linux 8."
                exit 1
            fi
        fi
        if [[ $ID == "amzn" ]]; then
            OS="amzn"
            if [[ $VERSION_ID != "2" ]]; then
                echo "⚠️ Ваша версия Amazon Linux не поддерживается."
                echo "Скрипт поддерживает только Amazon Linux 2."
                exit 1
            fi
        fi
    elif [[ -e /etc/arch-release ]]; then
        OS=arch
    else
        echo "Похоже, вы не используете этот установщик в системе Debian, Ubuntu, Fedora, CentOS, Amazon Linux 2, Oracle Linux 8 или Arch Linux."
        exit 1
    fi
}

# Функция для начальной проверки
function initialCheck() {
    isRoot
    tunAvailable
    checkOS
}

# Функция для установки пакетов с проверкой успешности и повторными попытками
function install_packages() {
    local install_command="$1"
    local attempt=1

    while [[ $attempt -le $MAX_INSTALL_ATTEMPTS ]]; do
        echo "Попытка установки пакетов (Попытка $attempt из $MAX_INSTALL_ATTEMPTS)..."
        eval "$install_command"

        # Проверка, установлен ли OpenVPN
        if command -v openvpn >/dev/null 2>&1; then
            echo "OpenVPN успешно установлен."
            return 0
        else
            echo "Ошибка: OpenVPN не установлен."
            ((attempt++))
            sleep 2
        fi
    done

    echo "Не удалось установить OpenVPN после $MAX_INSTALL_ATTEMPTS попыток."
    return 1
}

# Функция генерации ключей с проверкой успешности и повторными попытками
function generate_key() {
    local key_type=$1
    local key_path=$2
    local command="openvpn --genkey --secret $key_path"
    local attempt=1

    while [[ $attempt -le $MAX_KEY_GENERATION_ATTEMPTS ]]; do
        echo "Попытка $attempt: Генерация ключа $key_type..."
        eval "$command"

        if [[ -f $key_path && -s $key_path ]]; then
            echo "Ключ $key_type успешно сгенерирован!"
            return 0
        else
            echo "Ошибка при генерации ключа $key_type. Повторная попытка..."
        fi

        ((attempt++))
        sleep 1
    done

    echo "Не удалось сгенерировать ключ $key_type после $MAX_KEY_GENERATION_ATTEMPTS попыток."
    return 1
}

# Функция установки OpenVPN
function installOpenVPN() {
    if [[ ! -e /etc/openvpn/server.conf ]]; then
        if [[ $OS =~ (debian|ubuntu) ]]; then
            # Обновление и установка базовых пакетов
            INSTALL_CMD="apt-get update && apt-get -y install ca-certificates gnupg"
            install_packages "$INSTALL_CMD"
            if [[ $? -ne 0 ]]; then
                echo "Не удалось установить ca-certificates и gnupg."
                exit 1
            fi

            # Специфические действия для Ubuntu 16.04
            if [[ $OS == "ubuntu" && $VERSION_ID == "16.04" ]]; then
                echo "Добавление репозитория OpenVPN для Ubuntu 16.04..."
                echo "deb http://build.openvpn.net/debian/openvpn/stable xenial main" >/etc/apt/sources.list.d/openvpn.list
                wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
                INSTALL_CMD="apt-get update && apt-get -y install openvpn iptables openssl wget ca-certificates curl"
                install_packages "$INSTALL_CMD"
                if [[ $? -ne 0 ]]; then
                    echo "Не удалось установить OpenVPN на Ubuntu 16.04."
                    exit 1
                fi
            else
                # Установка OpenVPN и необходимых пакетов для Debian/Ubuntu
                INSTALL_CMD="apt-get install -y openvpn iptables openssl wget ca-certificates curl"
                install_packages "$INSTALL_CMD"
                if [[ $? -ne 0 ]]; then
                    echo "Не удалось установить OpenVPN на Debian/Ubuntu."
                    exit 1
                fi
            fi
        elif [[ $OS == 'centos' ]]; then
            INSTALL_CMD="yum install -y epel-release && yum install -y openvpn iptables openssl wget ca-certificates curl tar 'policycoreutils-python*'"
            install_packages "$INSTALL_CMD"
            if [[ $? -ne 0 ]]; then
                echo "Не удалось установить OpenVPN на CentOS."
                exit 1
            fi
        elif [[ $OS == 'oracle' ]]; then
            INSTALL_CMD="yum install -y oracle-epel-release-el8 && yum-config-manager --enable ol8_developer_EPEL && yum install -y openvpn iptables openssl wget ca-certificates curl tar policycoreutils-python-utils"
            install_packages "$INSTALL_CMD"
            if [[ $? -ne 0 ]]; then
                echo "Не удалось установить OpenVPN на Oracle Linux."
                exit 1
            fi
        elif [[ $OS == 'amzn' ]]; then
            INSTALL_CMD="amazon-linux-extras install -y epel && yum install -y openvpn iptables openssl wget ca-certificates curl"
            install_packages "$INSTALL_CMD"
            if [[ $? -ne 0 ]]; then
                echo "Не удалось установить OpenVPN на Amazon Linux 2."
                exit 1
            fi
        elif [[ $OS == 'fedora' ]]; then
            INSTALL_CMD="dnf install -y openvpn iptables openssl wget ca-certificates curl policycoreutils-python-utils"
            install_packages "$INSTALL_CMD"
            if [[ $? -ne 0 ]]; then
                echo "Не удалось установить OpenVPN на Fedora."
                exit 1
            fi
        elif [[ $OS == 'arch' ]]; then
            INSTALL_CMD="pacman --needed --noconfirm -Syu openvpn iptables openssl wget ca-certificates curl"
            install_packages "$INSTALL_CMD"
            if [[ $? -ne 0 ]]; then
                echo "Не удалось установить OpenVPN на Arch Linux."
                exit 1
            fi
        fi

        # Удаление старой версии easy-rsa, если она существует
        if [[ -d /etc/openvpn/easy-rsa/ ]]; then
            echo "Удаление старой версии easy-rsa..."
            rm -rf /etc/openvpn/easy-rsa/
        fi
    fi

    # Проверка наличия OpenVPN после установки
    if ! command -v openvpn >/dev/null 2>&1; then
        echo "OpenVPN не установлен. Проверьте подключение к Интернету и повторите попытку."
        exit 1
    fi

    # Продолжение установки OpenVPN (настройка, генерация ключей и т.д.)
    echo "Установка OpenVPN завершена. Продолжаю настройку..."
}

# Функция установки вопросов (параметров установки)
function installQuestions() {
    echo ""
    echo "Добро пожаловать в установщик OpenVPN от MineVPN!"
    echo ""

    # Отключение ненужных сервисов и удаление лог-файлов
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

    echo "Прежде чем приступить к настройке, параметры будут выбраны по умолчанию."
    echo ""

    # Получение IP-адреса
    IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)

    if [[ -z $IP ]]; then
        IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
    fi
    APPROVE_IP="y"
    
    # Проверка на NAT и получение публичного IP
    if echo "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
        echo "Сервер за NAT. Получение публичного IP..."
        PUBLICIP=$(curl -s https://api.ipify.org)
        ENDPOINT="$PUBLICIP"
    else
        ENDPOINT="$IP"
    fi

    echo "Используемый IP: $IP"
    echo "Публичный IP/Hostname: $ENDPOINT"

    # Проверка поддержки IPv6
    PING6="ping6 -c3 ipv6.google.com > /dev/null 2>&1"
    if eval "$PING6"; then
        IPV6_SUPPORT="y"
        echo "IPv6 поддерживается."
    else
        IPV6_SUPPORT="n"
        echo "IPv6 не поддерживается."
    fi

    # Выбор порта (по умолчанию случайный)
    PORT=$(shuf -i49152-65535 -n1)
    echo "Случайный порт: $PORT"

    # Выбор протокола (по умолчанию UDP)
    PROTOCOL="udp"
    echo "Используемый протокол: $PROTOCOL"

    # Выбор DNS (по умолчанию Google DNS)
    DNS="9"
    echo "Используемые DNS: Google (8.8.8.8, 8.8.4.4)"

    # Отключение сжатия (по умолчанию)
    COMPRESSION_ENABLED="n"
    echo "Сжатие отключено."

    # Параметры шифрования (по умолчанию)
    CIPHER="AES-128-CBC"
    CERT_TYPE="1" # ECDSA
    CERT_CURVE="prime256v1"
    CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
    DH_TYPE="1" # ECDH
    DH_CURVE="prime256v1"
    HMAC_ALG="SHA256"
    TLS_SIG="2" # tls-auth
    echo "Параметры шифрования выбраны по умолчанию."

    echo ""
    echo "Настройка завершена. Ваш OpenVPN-сервер готов к установке."
    echo "Вы сможете создать VPN конфиг в конце установки."

    # Автоматическое продолжение
    APPROVE_INSTALL="y"
}

# Функция генерации клиентских конфигураций
function newClient() {
    local CLIENT=$1
    PASS="1"

    CLIENTEXISTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c -E "/CN=$CLIENT\$")

    if [[ $CLIENTEXISTS == '1' ]]; then
        echo ""
        echo "Указанный CN клиента уже найден в easy-rsa, выберите другое имя."
        exit 1
    else
        cd /etc/openvpn/easy-rsa/ || return
        case $PASS in
        1)
            ./easyrsa build-client-full "$CLIENT" nopass
            ;;
        2)
            echo "⚠️ Вам будет предложено ввести пароль ниже ⚠️"
            ./easyrsa build-client-full "$CLIENT"
            ;;
        esac
        echo "Конфиг $CLIENT создан."
    fi

    if [ -e "/home/${CLIENT}" ]; then
        homeDir="/home/${CLIENT}"
    elif [ "${SUDO_USER}" ]; then
        if [ "${SUDO_USER}" == "root" ]; then
            homeDir="/root"
        else
            homeDir="/home/${SUDO_USER}"
        fi
    else
        homeDir="/root"
    fi

    if grep -qs "^tls-crypt" /etc/openvpn/server.conf; then
        TLS_SIG="1"
    elif grep -qs "^tls-auth" /etc/openvpn/server.conf; then
        TLS_SIG="2"
    fi

    cp /etc/openvpn/client-template.txt "$homeDir/$CLIENT.ovpn"

    {
        echo "<ca>"
        cat "/etc/openvpn/easy-rsa/pki/ca.crt"
        echo "</ca>"

        echo "<cert>"
        awk '/BEGIN/,/END/' "/etc/openvpn/easy-rsa/pki/issued/$CLIENT.crt"
        echo "</cert>"

        echo "<key>"
        cat "/etc/openvpn/easy-rsa/pki/private/$CLIENT.key"
        echo "</key>"

        case $TLS_SIG in
        1)
            if [[ -s /etc/openvpn/tls-crypt.key ]]; then
                echo "<tls-crypt>"
                cat /etc/openvpn/tls-crypt.key
                echo "</tls-crypt>"
            else
                echo "Ошибка: tls-crypt.key не найден или пуст."
                exit 1
            fi
            ;;
        2)
            if [[ -s /etc/openvpn/tls-auth.key ]]; then
                echo "key-direction 1"
                echo "<tls-auth>"
                cat /etc/openvpn/tls-auth.key
                echo "</tls-auth>"
            else
                echo "Ошибка: tls-auth.key не найден или пуст."
                exit 1
            fi
            ;;
        esac
    } >>"$homeDir/$CLIENT.ovpn"

    echo ""
    echo "Файл конфигурации был записан в $homeDir/$CLIENT.ovpn."
}

# Функция удаления OpenVPN
function removeOpenVPN() {
    echo ""
    REMOVE="y"
    if [[ $REMOVE == 'y' ]]; then
        PORT=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)
        PROTOCOL=$(grep '^proto ' /etc/openvpn/server.conf | cut -d " " -f 2)

        if [[ $OS =~ (fedora|arch|centos|oracle) ]]; then
            systemctl disable openvpn-server@server
            systemctl stop openvpn-server@server
            rm /etc/systemd/system/openvpn-server@.service
        elif [[ $OS == "ubuntu" ]] && [[ $VERSION_ID == "16.04" ]]; then
            systemctl disable openvpn
            systemctl stop openvpn
        else
            systemctl disable openvpn@server
            systemctl stop openvpn@server
            rm /etc/systemd/system/openvpn@.service
        fi

        systemctl stop iptables-openvpn
        systemctl disable iptables-openvpn
        rm /etc/systemd/system/iptables-openvpn.service
        systemctl daemon-reload
        rm /etc/iptables/add-openvpn-rules.sh
        rm /etc/iptables/rm-openvpn-rules.sh

        if hash sestatus 2>/dev/null; then
            if sestatus | grep "Current mode" | grep -qs "enforcing"; then
                if [[ $PORT != '1194' ]]; then
                    semanage port -d -t openvpn_port_t -p "$PROTOCOL" "$PORT"
                fi
            fi
        fi

        if [[ $OS =~ (debian|ubuntu) ]]; then
            apt-get remove --purge -y openvpn
            if [[ -e /etc/apt/sources.list.d/openvpn.list ]]; then
                rm /etc/apt/sources.list.d/openvpn.list
                apt-get update
            fi
        elif [[ $OS == 'arch' ]]; then
            pacman --noconfirm -R openvpn
        elif [[ $OS =~ (centos|amzn|oracle) ]]; then
            yum remove -y openvpn
        elif [[ $OS == 'fedora' ]]; then
            dnf remove -y openvpn
        fi

        find /home/ -maxdepth 2 -name "*.ovpn" -delete
        find /root/ -maxdepth 1 -name "*.ovpn" -delete
        rm -rf /etc/openvpn
        rm -rf /usr/share/doc/openvpn*
        rm -f /etc/sysctl.d/99-openvpn.conf
        rm -rf /var/log/openvpn

        echo ""
        echo "OpenVPN удален!"
    else
        echo ""
        echo "Удаление прервано!"
    fi
}

# Функция установки OpenVPN и его конфигурации
function installOpenVPNConfiguration() {
    # Генерация статического TLS-ключа с проверкой
    case $TLS_SIG in
        1)
            generate_key "tls-crypt" "/etc/openvpn/tls-crypt.key"
            ;;
        2)
            generate_key "tls-auth" "/etc/openvpn/tls-auth.key"
            ;;
    esac

    # Проверка успешности генерации ключей
    if [[ $? -ne 0 ]]; then
        echo "Не удалось сгенерировать необходимые TLS-ключи. Прерывание установки."
        exit 1
    fi

    # Продолжение установки OpenVPN (настройка, конфигурация и т.д.)
    # Вставьте здесь ваш существующий код настройки OpenVPN
}

# Функция генерации клиента OpenVPN
function generateClientConfig() {
    # Ваш существующий код для генерации клиентских конфигураций
    # Убедитесь, что вызывается только после успешной установки и генерации ключей
    :
}

# Функция главного меню
function main() {
    if [[ "$1" == "-b" && "$2" != "" && "$3" == "-c" && "$4" != "" ]]; then
        local baseName=$2
        local clientCount=$4

        initialCheck
        installOpenVPN

        if [[ -e /etc/openvpn/server.conf && $AUTO_INSTALL != "y" ]]; then
            removeOpenVPN
            installOpenVPN
        else
            installOpenVPN
        fi

        # Генерация конфигураций клиентов
        for ((i = 1; i <= clientCount; i++)); do
            newClient "${baseName}-${i}"
        done
    else
        echo "Использование: $0 -b CLIENT_BASE_NAME -c CLIENT_COUNT"
        exit 1
    fi
}

# Вызов главной функции с передачей всех аргументов
main "$@"
