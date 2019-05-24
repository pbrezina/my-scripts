#!/bin/bash

remove-trailing-spaces() {
    find . -name "$1" -type f -print0 | xargs -0 sed -i -E "s/[[:space:]]*$//"
}

mygit-push-diff() {
    for branch in "$@"
    do
        echo   "* \`$branch\`"
        format="  * %Cred%H%Creset - %s"
        git log --pretty="format:$format" origin/$branch..$branch
    done
}

mygit-commit-diff() {
    format="%Cred%h%Creset - %s%C(yellow)%d%Creset %Cgreen(%cr)%Creset"
    git log --pretty=format:$format origin/$1..$1
    git log --graph --pretty="format:$format" --abbrev-commit --date=relative $1..$2
}