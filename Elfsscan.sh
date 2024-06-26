#!/bin/bash -p


RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

# 危险函数
function_arr=("system" "popen" "execve")

dir_path="."

# 解析脚本参数
use_fuzzy_search=false
while getopts "f" opt; do
    case ${opt} in
        f )
            use_fuzzy_search=true
            ;;
        \? )
            echo "Usage: cmd [-f]"
            exit 1
            ;;
    esac
done

file_arr=($(find "$dir_path" -type f))

for file in "${file_arr[@]}"
do
    if file "${file}" | grep -q "ELF"; then
        if $use_fuzzy_search; then
            # 使用模糊查询
            mapfile -t result < <(readelf -s --use-dynamic "${file}" 2> /dev/null | grep -Ei "$(IFS='|'; echo "${function_arr[*]}")" | grep -v "file format" || true)
        else
            # 使用正常查询
            mapfile -t result < <(readelf -s --use-dynamic "${file}" 2> /dev/null | grep -E "$(IFS='|'; echo "${function_arr[*]}")" | grep -v "file format" || true)
        fi

        if [ ${#result[@]} -eq 0 ]; then
            continue
        fi
        echo -e "${GREEN}<------------------------------${file}------------------------------>${GREEN}"
        for fun in "${result[@]}"
        do
            function_name=$(echo "$fun" | awk '{print $NF}')
            echo -e "${YELLOW}----------------${function_name}----------------${YELLOW}"
            mapfile -t dumpresult < <(objdump -d ${file} | grep ${function_name})
            if [ ${#dumpresult[@]} -le 30 ]; then
                for dresult in "${dumpresult[@]}"
                do
                    echo -e "${YELLOW}${dresult}${NC}"
                done
            else
                echo -e "${RED}There are too many function calls, only 10 are displayed${RED}"
                int=1
                while(( $int<=10 ))
                do
                    echo -e "${YELLOW}${dumpresult[$int]}${NC}"
                    let "int++"
                done  
            fi
        done
    else
        continue
    fi
done
