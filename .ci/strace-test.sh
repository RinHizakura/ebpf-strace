#!/usr/bin/env bash

STRACE_LOG="/tmp/strace.log"
OUTPUT_LOG="/tmp/output.log"
BIN=${BIN:-"target/debug/ebpf-strace"}

r=$'\r'
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

RETURN=0
FAIL_STOP=0
OUT_DIR="target/debug/tests"

if [ $# -gt 0 ]; then
    FILES=""
    for name in "$@"; do
        f="${name}.out"
        if [ ! -f "$OUT_DIR/$f" ]; then
            echo "error: test not found: $OUT_DIR/$f"
            exit 1
        fi
        FILES="$FILES $f"
    done
else
    FILES=$(ls $OUT_DIR | grep '.out')
fi

TOTAL=$(echo ${FILES} | wc -w)
TEST_NUM=0
PASS=0

for FILE in ${FILES}; do
    RSLT=0
    TEST_NUM=$((TEST_NUM+1))
    CMD="sudo $BIN $OUT_DIR/$FILE"
    sudo $CMD 2>$STRACE_LOG 1>$OUTPUT_LOG
    sed -i 's/)[[:blank:]]*=[[:blank:]]/) = /g' $STRACE_LOG

    echo -n "[$TEST_NUM/$TOTAL] run test: ${FILE}..."

    n=1
    while read -r line; do
        rslt=`grep -Fx -- "$line" $STRACE_LOG`
        if [ "$rslt" = "" ] ; then
            RSLT=1
            break
        fi
        n=$((n+1))
    done < $OUTPUT_LOG

    if [ $RSLT != 0 ] ; then
        echo -e "${r}[$TEST_NUM/$TOTAL] run test: ${FILE}... ${RED}fail${NC}"
        syscall="${FILE%.out}"
        echo "Fail at line $n:"
        echo "  expected: $normalized"
        echo "  strace log (grep $syscall):"
        grep "^$syscall" $STRACE_LOG | sed 's/^/    /'
        RETURN=1
        if [ $FAIL_STOP = 1 ] ; then
            break;
        fi
    else
        echo -e "${r}[$TEST_NUM/$TOTAL] run test: ${FILE}... ${GREEN}pass${NC}"
        PASS=$((PASS+1))
    fi

done

echo "pass rate: ${PASS}/${TOTAL}"

exit $RETURN
