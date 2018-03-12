#!/bin/bash

remove-trailing-spaces() {
    find . -name "$1" -type f -print0 | xargs -0 sed -i -E "s/[[:space:]]*$//"
}
