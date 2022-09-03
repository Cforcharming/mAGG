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

echo -e "\nChecking if dependencies are installed...\n"

function add() {
    pac=$1
    if ! [[ $(type -p "$pac") ]]; then
        type "$pac"
        not_installed+=("$pac")
    else
        type "$pac"
    fi
}

not_installed=()

add python3
add docker
add docker-compose
add go

echo installing following dependencies:

for t in "${not_installed[@]}"; do
        echo "$t"
done
echo

case $ID_LIKE in

    macOS)
        echo using homebrew "$(type -p brew)"
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
             brew install python
             brew install --cask docker
             brew install go
        done
    ;;

    arch)
        for t in "${not_installed[@]}"; do
             sudo pacman --noconfirm -S "$t"
        done

        echo
        sudo systemctl enable docker --now
    ;;

    debian)
        if ! [[ -f /etc/apt/sources.list.d/docker.list ]]; then
            echo adding docker deb sources...
            if [[ $NAME == *"Ubuntu"* ]]; then
                curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
                echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list

            elif [[ $NAME == *"Debian"* ]]; then
                curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
                echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list
            fi
            echo
            sudo apt update
        fi

        echo
        for t in "${not_installed[@]}"; do
             if [[ $t == "go" ]]; then
                 sudo apt-get -y install golang
             elif [[ $t == "docker" ]]; then
                 sudo apt-get -y install docker-ce docker-ce-cli containerd.io docker-compose-plugin
             else
                 sudo apt-get -y install "$t"
             fi
        done

        echo
        sudo systemctl enable docker --now
    ;;
esac

echo -e "\n creating venv $PWD/venv/$ID_LIKE\n"
mkdir -p venv
python3 -m venv "$PWD/venv/$ID_LIKE"
# shellcheck source=/dev/null
if [[ -f "venv/$ID_LIKE/bin/activate" ]]; then
    source venv/$ID_LIKE/bin/activate
else
    echo -e "\n installing as global modules."
fi

echo -e "\n installing required pip modules.\n"
python -m pip install --upgrade pip
pip install -r requirements.txt

echo
# clairctl
type clairctl || curl -L https://raw.githubusercontent.com/jgsqware/clairctl/master/install.sh | sudo sh
clairctl_path="$HOME/go/src/github.com/jgsqware/clairctl"
! [[ -e $clairctl_path ]] || git clone --depth=1 https://github.com/jgsqware/clairctl.git "$HOME/go/src/github.com/jgsqware"
