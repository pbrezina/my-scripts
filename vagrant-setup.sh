#!/bin/bash
#
# Setup Vagrant environment.
#

if [ x$VAGRANT == "xyes" ] ; then
    # We are on vagrant machine.

    export PS1="[\u@\H \w$MY_GIT_PROMPT]$MY_PS1_SIGN "
fi

# We are on host machine.

export SSSD_TEST_SUITE_BASHRC="/shared/workspace/my-scripts/vagrant-bashrc.sh"
export SSSD_TEST_SUITE_SSHFS=""

SSSD_TEST_SUITE_SSHFS="$MY_WORKSPACE:/shared/workspace"
