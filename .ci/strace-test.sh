#!/usr/bin/env bash

BIN="target/debug/ebpf-strace"
STRACE_LOG="/tmp/strace.log"
OUTPUT_LOG="/tmp/output.log"

r=$'\r'
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

RETURN=0
FAIL_STOP=1
FILES=$(ls build | grep '.out')
for FILE in ${FILES}; do
    RSLT=0
    sudo $BIN build/$FILE 2>$STRACE_LOG 1>$OUTPUT_LOG

    echo -n "run test: ${FILE}..."

    n=1
    while read line; do
        rslt=`grep -Fx -- "$line" $STRACE_LOG`
        if [ "$rslt" = "" ] ; then
            RSLT=1
            break
        fi
        n=$((n+1))
    done < $OUTPUT_LOG

    if [ $RSLT != 0 ] ; then
        echo -e "${r}run test: ${FILE}... ${RED}fail${NC}"
        echo "Fail at line $n: can't match $line"
        RETURN=1
        if [ $FAIL_STOP = 1 ] ; then
            break;
        fi
    else
        echo -e "${r}run test: ${FILE}... ${GREEN}pass${NC}"
    fi

done

exit $RETURN
