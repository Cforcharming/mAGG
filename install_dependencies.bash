#!/usr/bin/env bash

# This script is tested on following systems, but is assumed to be running on different versions as well as Debian:
# macOS 12.3.1
# Manjaro Rolling (in 2022.5)
# Ubuntu 22.04 LTS
# Kali Rolling 2022.2.4
#
# Alternatively, you can install the dependencies manually, for details please see README.md

sudo -v

function exit_on_invalid_host() {

    case $kernel_name in
        SunOS) ID_LIKE=Solaris ;;
        Haiku) ID_LIKE=Haiku ;;
        MINIX) ID_LIKE=MINIX ;;
        AIX) ID_LIKE=AIX ;;
        IRIX*) ID_LIKE=IRIX ;;
        FreeMiNT) ID_LIKE=FreeMiNT ;;
        CYGWIN*|MSYS*|MINGW*) ID_LIKE=Windows ;;
        *) ID_LIKE='' ;;
    esac

    printf '%s\n' "Unsupported OS detected: '$ID_LIKE' '$kernel_name', aborting..." >&2
            printf '%s\n' "Open an issue on GitHub to add support for your OS." >&2
            exit 1
}

IFS=" " read -ra uname <<< "$(uname -srm)"

kernel_name="${uname[0]}"

# $kernel_name is set in the output of "uname -s".
case $kernel_name in
    Darwin) ID_LIKE=macOS;;
    Linux|GNU*)
        if [[ -f /etc/os-release ]]; then
            source /etc/os-release
        else
            exit_on_invalid_host
        fi
        if [[ $ID_LIKE != "arch" ]] && [[ $ID_LIKE != "debian" ]]; then
            exit_on_invalid_host
        fi
    ;;
    *) exit_on_invalid_host ;;
esac

echo -e "\nChecking if dependencies are installed..."

function add() {
    pac=$1
    if ! [[ $(type -p "$pac") ]]; then
        if ! [[ $pac != "graphviz" ]]; then
            not_installed+=("$pac")
        else
            type -p dot > /dev/null || not_installed+=("$pac")
        fi
    fi
}

not_installed=()

add python3
add docker
add docker-compose
add go
add graphviz

case $ID_LIKE in

    macOS)
        if ! [[ $(type -p brew) ]]; then
            echo installing homebrew...
            bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            e=$?
            if ! [[ $e -eq 0 ]]; then
                echo Homebrew install failed. Please install dependencies manually.
                exit $e
            fi
        fi

        for t in "${not_installed[@]}"; do
             brew install "$t"
        done
        brew link --force docker
    ;;

    arch)
        for t in "${not_installed[@]}"; do
             sudo pacman -S "$t"
        done
        sudo systemctl enable docker
        sudo systemctl start docker
    ;;

    debian)
        if ! [[ -f /etc/apt/sources.list.d/docker.list ]]; then
            if [[ $NAME == *"Ubuntu"* ]]; then
                curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
                echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

            elif [[ $NAME == *"Debian"* ]]; then
                curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
                echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
            fi
            sudo apt update
        fi


        for t in "${not_installed[@]}"; do
             if [[ $t == "go" ]]; then
                 sudo apt-get -y install golang
             elif [[ $t == "docker" ]]; then
                 sudo apt-get -y install docker-ce docker-ce-cli containerd.io docker-compose-plugin
             else
                 sudo apt-get -y install "$t"
             fi
        done

        sudo systemctl enable docker
        sudo systemctl start docker
    ;;
esac

mkdir -p venv
python3 -m venv "$PWD/venv/$ID_LIKE"
# shellcheck source=/dev/null
source "venv/$ID_LIKE/bin/activate"
python -m pip install --upgrade pip
pip install -r requirements.txt

# clairctl
type -p clairctl > /dev/null || curl -L https://raw.githubusercontent.com/jgsqware/clairctl/master/install.sh | sudo sh
