#!/bin/bash

tcmount() {
    VOL=${1-$HOME/gdrive/personal/secrets.tc}
    DEV=${2-TRUECRYPT}
    echo "Mounting $VOL"
    sudo cryptsetup open --type tcrypt $VOL $DEV
    sudo mkdir /media/$DEV
    sudo mount -o uid=1000 /dev/mapper/TRUECRYPT /media/$DEV
}

tcumount() {
    DEV=${1-TRUECRYPT}
    sudo umount /media/$DEV
    sudo rmdir /media/$DEV
    sudo cryptsetup close $DEV
}
