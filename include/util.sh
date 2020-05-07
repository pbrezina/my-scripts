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

mygit-fixed-issues() {
    issues=`git log $2..HEAD | grep "https://github.com/.*/$1/issues" | uniq`
    for issue in $issues; do
        issue=`echo "$issue" | sed "s|.*/||"`
        hub issue show -f '* %i - %t%n' $issue
    done
}

rst-to-md() {
    md=`basename -s .rst $i`.md
    pandoc --wrap=none -f rst -t markdown_strict -o $md $1
    sed -i -E 's/<span class="title-ref">(.*)<\/span>/`\1`/g' $md &> /dev/null
    sed -i -E 's/> //g' $md &> /dev/null
    sed -i -E 's/-   /- /g' $md &> /dev/null
    sed -i -E 's/    -/  -/g' $md &> /dev/null
    sed -i -E 's/\\\[/[/g' $md &> /dev/null
    sed -i -E 's/\\\]/]/g' $md &> /dev/null
    sed -i -E 's/\\_/_/g' $md &> /dev/null
    sed -i -E 's/\[(.*)\]\(\)\\\*/`\1*()`/g' $md &> /dev/null
    sed -i -E 's/\[(.*)\]\(\)/`\1()`/g' $md &> /dev/null

}