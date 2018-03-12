#!/bin/bash

__DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

success_or_die() {
    if [ $1 -ne 0 ]; then
        echo $2
        exit 1
    fi
}

read_lines()
{
    local FILE="$__DIR/$1"
    local LINES=`sed '/^#.*$/d' $FILE`

    echo $LINES
}

read_list()
{
    local LINES=`read_lines $1`
    local LIST=""
    
    for line in $LINES; do
        LIST+=" $line"
    done
    
    echo $LIST
}

create_repository()
{
    if [[ "$1" == *.repo ]]; then
        local NAME=`basename "$repo"`
        sudo wget -q "$1" -O /etc/yum.repos.d/$NAME
        return 0
    fi  
    
    local NAME=`echo "$1" | sed 's/^\([^=]\{1,\}\)=\(.\{1,\}\)$/\1/g'`
    local LINK=`echo "$1" | sed 's/^\([^=]\{1,\}\)=\(.\{1,\}\)$/\2/g'`
    local REPO="[$NAME]\nname=$NAME\nbaseurl=$LINK\nenabled=1\n"

    sudo bash -c "echo -e '$REPO' > '/etc/yum.repos.d/$NAME.repo'"
}

echo "Provisioning system!"

echo "1. Setup passwordless sudo (provide root password)"
su root -c "sed 's/user/$USER/g' $__DIR/sudoers > /etc/sudoers ; chmod a=r,o-r /etc/sudoers"
success_or_die $? "Unable to setup passwordless sudo!"

echo "2. Updating installed packages"
sudo dnf upgrade --nogpgcheck -y
success_or_die $? "Unable to upgrade packages!"

echo "3. Installing RPM certificates"
for cert in `read_lines certificates`; do
    sudo rpm --import "$cert"
    success_or_die $? "Unable to install certificate $cert!"
done

echo "4. Enabling additional repositories"
if [ ! -f /etc/yum.repos.d/rpmfusion-free.repo ]; then
    sudo dnf install --nogpgcheck -y \
        https://download1.rpmfusion.org/free/fedora/rpmfusion-free-release-$(rpm -E %fedora).noarch.rpm
    success_or_die $? "Unable to install rpm fusion free repository!"
fi

if [ ! -f /etc/yum.repos.d/rpmfusion-nonfree.repo ]; then
    sudo dnf install --nogpgcheck -y \
        https://download1.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-$(rpm -E %fedora).noarch.rpm
    success_or_die $? "Unable to install rpm fusion non-free repository!"
fi

for repo in `read_lines repositories`; do
    create_repository $repo
    success_or_die $? "Unable to install repository: $repo"
done

for repo in `read_lines copr`; do
    sudo dnf copr enable -y $repo
    success_or_die $? "Unable to enable copr repository: $repo"
done

echo "5. Installing required packages"
sudo dnf install --nogpgcheck -y `read_list packages`
success_or_die $? "Unable to install packages!"

echo "6. Installing debug information"
sudo dnf debuginfo-install -y `read_list debuginfo`
success_or_die $? "Unable to install debug information!"

echo "7. Update PIP"
sudo pip install --upgrade pip
success_or_die $? "Unable to upgrade python packages!"

echo "8. Provision machine with Ansible"
ansible-playbook -i "localhost," -c local "$__DIR/ansible/playbook.yml"
success_or_die $? "Unable to provision machine with ansible scripts!"

echo ""
echo "System is successfully installed!"
