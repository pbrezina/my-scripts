#!/bin/bash

# My Environment Setup
#
# This file should be included from .bashrc and these environment variables
# should be defined:
# MY_USER_HOME    -- path to main user home directory
# MY_SCRIPTS_PATH -- path to scripts directory where this file is located
#
# Example .bashrc:
#   MY_USER_HOME="/home/pbrezina"
#   MY_SCRIPTS_PATH="$MY_USER_HOME/workspace/scripts"
#   MY_BASHRC="$MY_SCRIPTS_PATH/environment-setup.sh"
# 
#   if [ ! -f $MY_BASHRC ]; then
#       echo "Missing file: $MY_BASHRC"
#       return 1
#   fi
# 
#   . $MY_BASHRC
#

# Source global definitions
if [ -f /etc/bashrc ]; then
    . /etc/bashrc
fi

# Source git bash-completion
if [ -f /usr/share/git-core/contrib/completion/git-prompt.sh ]; then
    . /usr/share/git-core/contrib/completion/git-prompt.sh
    GIT_PS1_SHOWDIRTYSTATE="yes"
    GIT_PS1_SHOWUNTRACKEDFILES="yes"
    MY_GIT_PROMPT='$(__git_ps1 " (%s)")'
fi

export MY_PS1_SIGN="\$"
if [[ $EUID -eq 0 ]]; then
    export MY_PS1_SIGN="#"
fi

export PS1="[\u \w$MY_GIT_PROMPT]$MY_PS1_SIGN "
export MY_WORKSPACE="$MY_USER_HOME/workspace"
export MY_INCLUDE="$MY_SCRIPTS_PATH/include $MY_WORKSPACE/sssd-dev-utils"

# Setup SSSD Developer Tools
export SSSD_SOURCE=$MY_WORKSPACE/sssd
export SSSD_BUILD=/dev/shm/sssd
export SSSD_TEST_DIR=/dev/shm/sssd-tests
export SSSD_USER=root
export SSSD_RHEL_PACKAGE=$MY_USER_HOME/packages/rhel/sssd
export CFLAGS_CUSTOM=""

export GIT_PATCH_LOCATION="$MY_USER_HOME/Downloads"
export GIT_DEVEL_REPOSITORY="devel"
export GIT_PUSH_REPOSITORIES="pbrezina"

export NTP_SERVER="master.ipa.vm"

# PHP Development
export XDEBUG_CONFIG="idekey=VSCODE"

. $MY_SCRIPTS_PATH/vagrant-setup.sh
. $MY_SCRIPTS_PATH/include-scripts.sh
