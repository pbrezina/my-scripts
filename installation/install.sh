#!/bin/bash

__DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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

    sudo bash -c "echo -e '$REPO' > /etc/yum.repos.d/$NAME.repo"
}

echo "Provisioning system!"

echo "1. Setup passwordless sudo (provide root password)"
#su root -c "sed 's/user/$USER/g' $__DIR/sudoers > /etc/sudoers ; chmod a=r,o-r /etc/sudoers"

echo "2. Updating installed packages"
#sudo dnf upgrade --nogpgcheck -y

echo "3. Enabling additional repositories"
for repo in `read_lines repositories`; do
    create_repository $repo
done

echo "4. Installing required packages"
#sudo dnf install --nogpgcheck -y `read_list packages`

echo "5. Installing debug information"
#sudo dnf debuginfo-install -y `read_list debuginfo`

echo "6. Update PIP"
#sudo pip install --upgrade pip

echo "7. Provision machine with Ansible"
#ansible-playbook -i "localhost," -c local "./ansible/playbook.yml"

echo ""
echo "System is successfully installed!"
