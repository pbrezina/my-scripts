#!/bin/bash
# Include all files and directories referenced by MY_INCLUDE variable.

for INCLUDE_PATH in $MY_INCLUDE ; do
    if [ -f $INCLUDE_PATH ]; then
        . $INCLUDE_PATH
    fi

    # Include all shell scripts from directory, ordered by name
    FILES=`find $INCLUDE_PATH -type f -name '*.sh' -printf '%d\t%p\n'`
    for FILE in `echo $FILES | sort -nk1 | cut -f2-` ; do
        if [ -f $FILE ]; then
            . $FILE
        fi
    done
done
