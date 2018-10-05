#!/bin/bash

__DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

success_or_die() {
    if [ $1 -ne 0 ]; then
        echo $2
        exit 1
    fi
}

echo "Provisioning system!"

echo "1. Setup passwordless sudo (provide root password)"
su root -c "sed 's/user/$USER/g' $__DIR/sudoers > /etc/sudoers ; chmod a=r,o-r /etc/sudoers"
success_or_die $? "Unable to setup passwordless sudo!"

echo "2. Install Ansible"
sudo dnf install -y ansible > /dev/null
success_or_die $? "Unable to install Ansible!"

echo "3. Provision machine with Ansible"
ansible-playbook                                     \
    -i "localhost,"                                  \
    -c local                                         \
    -e "ansible_python_interpreter=/usr/bin/python3" \
    "$__DIR/ansible/playbook.yml"
success_or_die $? "Unable to provision machine with ansible scripts!"

echo ""
echo "System is successfully installed!"
