#!/bin/bash
# Cert-Scanner.sh = Private certificate scanner (.jks or .pem types) in a GitHub repo.
#   Can operate in 3 modes:
#     1) l = List: all private certs in a table
#     2) w = Warning: Find any expiring certs and notify via Jira ticket
#     3) b = Both List & Warning modes

# Date Expiry Function
cert_expiry_check() {
    #param check
    echo "name= $1"
    echo "certExp= $2"
    echo "certFile= $3"
    echo "certType= $4"

    #setup dates
    epoch_day=60*60*24 #sec*min*hour
    days_expire=$DAYS
    epoch_warn=$(( days_expire*epoch_day ))
    #echo "epoch warn=$epoch_warn"

    today_epoch="$(date +%s)"
    #echo "today=$today_epoch"

    # expire_epoch=$(date +%s -d "$2") # Uncomment for LINUX (GH Runners)
    # BSD/MacOS VERSION of DATE (PEM & JKS need diff format conversion) - toggle off for Linux
    if [[ $4 = "PEM" ]]; then
      expire_epoch=$(date -j -f "%b %d %T %Y %Z" "$2" "+%s") 
    else
      expire_epoch=$(date -j -f "%a %b %d %T %Z %Y" "$2" "+%s")
    fi
    echo "epoch=$expire_epoch"

    timeleft=`expr $expire_epoch - $today_epoch`
    daysleft=$(( timeleft/epoch_day ))
    echo "time_epoch= $timeleft  days_left= $daysleft"

    if [[ $timeleft -le $epoch_warn ]]; then
        CERT_WARN="WARNING = $certFile expires $expire_date (in $daysleft days).  Certificate Name: $1"
        echo "****** $CERT_WARN ******"
        ### OFF - No spam Jira ###
        # echo '10.250.16.130 jira.apptio.com' | sudo tee -a /etc/hosts
        # SUMMARY="GH Cert Scan: Warning - Cert Expiring soon. File: $certFile"
        # echo "sum= $SUMMARY"
        # DATA='{"fields":{"project":{"key": "CCM"},"summary":"'
        # DATA+=${SUMMARY}
        # DATA+='","description": "'
        # DATA+=${CERT_WARN}
        # DATA+='","issuetype": {"name": "Bug"}}}'
        # echo "data= $DATA"
        # curl -D- -u $JIRA_USER:$JIRA_API_TOKEN -X POST --data "$DATA" -H "Content-Type: application/json" https://jira.apptio.com/rest/api/2/issue/
    else
        echo "******* NO CERT EXPIRY DETECTED - Expires in $daysleft days ******"
    fi
}

# Detect params to run
# - mode: l=list only | w=warning only | b=both
# - days: # of days before warning of expiring cert (only for warning mode)
while getopts "m:d:" options
do
    case "${options}"
        in
        m)MODE=${OPTARG};;
        d)DAYS=${OPTARG};;
    esac
done

echo "Mode: $MODE"
echo "Warning Time (days)  : $DAYS"

# LOCAL CONFIG SECTION - control where scanner runs
# DEFAULT = Hack dir (BIIT) jks only # expired cert
# cd /Users/OPerzia/git2/apptio-bi/tron  #TRON (pem only)
# cd /Users/OPerzia/git2/ccm/cloud-service  #CCM (jks & pem)
# cd /Users/OPerzia/git2/apptio-bi/ssr/ssa-app  #SSA (2 pem)
pwd

IFS=$'\n'  # IFS: Allow splitting files found to be 1/line in array
# Find all .PEM & .JKS files in repo
PEM_ARRAY=($(find . -type f -name "*.pem"))
JKS_ARRAY=($(find . -type f -name "*.jks"))

# get number of elements in the array
PEM_COUNT=${#PEM_ARRAY[@]}
echo ".PEM files= $PEM_COUNT"
JKS_COUNT=${#JKS_ARRAY[@]}
echo ".JKS files= $JKS_COUNT"

# WARNING MODE: Find certs expiring under X days from now
if [[ ($MODE = 'w' || $MODE = 'b') && $DAYS -gt 0 ]]; then
    echo "Start - Cert Expiry mode"
    echo " - Cert Expiry => PEM"
    # For each PEM file: extract name (subject) & expiry date (enddate) & build table
    for (( i=0;i<$PEM_COUNT;i++ )); do
        PEM_DATA=($(openssl x509 -noout -subject -enddate -in ${PEM_ARRAY[${i}]} 2>/dev/null | sed -e 's/.*subject= \(.*\)/\1/' | sed -e 's/.*notAfter=\(.*\)/\1/' ))
        PEM_DATA_COUNT=${#PEM_DATA[@]}
        echo "PEM DATA Count= $PEM_DATA_COUNT"
        x=0
        while (( x < $PEM_DATA_COUNT )); do
            echo "x1=${x}"
            CERT_NAME_PEM=${PEM_DATA[${x}]}
            (( x += 1 ))
            echo "x2=${x}"
            CERT_EXPIRY=${PEM_DATA[${x}]}
            cert_expiry_check $CERT_NAME_PEM $CERT_EXPIRY ${PEM_ARRAY[${i}]} PEM
            (( x += 1 ))
        done
    done

    # For each JKS file: extract name (subject) & expiry date (enddate) & build table
    echo " - Cert Expiry => JKS"
    for (( i=0;i<$JKS_COUNT;i++ )); do
        JKS_DATA=($(echo | keytool -v -list -keystore ${JKS_ARRAY[${i}]} 2>/dev/null | grep -i 'Alias name\|Valid' | sed -e 's/.*name: \(.*\)/\1/' | sed -e 's/.*until: \(.*\)/\1/'))
        JKS_DATA_COUNT=${#JKS_DATA[@]}
        echo "JKS DATA Count= $JKS_DATA_COUNT"
        x=0
        while (( x < $JKS_DATA_COUNT )); do
            echo "x1=${x}"
            CERT_NAME_JKS=${JKS_DATA[${x}]}
            (( x += 1 ))
            echo "x2=${x}"
            CERT_EXPIRY=${JKS_DATA[${x}]}
            cert_expiry_check $CERT_NAME_JKS $CERT_EXPIRY ${JKS_ARRAY[${i}]} JKS
            (( x += 1 ))
        done
    done
fi

### LIST MODE ###
if [[ $MODE = "l" || $MODE = "b" ]]; then
    echo "Start - Cert List mode"
    # Create file and headers (csv & md formats)
    echo "Path: Cert File,Cert Name,Expiry Date" > certlist.csv
    echo "| Path: Cert File | Cert Name | Expiry Date |" > certlist.md
    echo "| --------------- | --------- | ----------- |" >> certlist.md

    # For each PEM file: extract name (subject) & expiry date (enddate) & build table
    echo " - Cert List mode => PEM"
    for (( i=0;i<$PEM_COUNT;i++ )); do
        echo "PEM_file=${PEM_ARRAY[${i}]}"
        CSV_LINE_PEM="${PEM_ARRAY[${i}]},"
        MD_LINE_PEM="| ${PEM_ARRAY[${i}]} |"
        PEM_DATA=($(openssl x509 -noout -subject -enddate -in ${PEM_ARRAY[${i}]} 2>/dev/null | sed -e 's/.*subject= \(.*\)/\1/' | sed -e 's/.*notAfter=\(.*\)/\1/' ))
        PEM_DATA_COUNT=${#PEM_DATA[@]}
        echo "PEM DATA Count= $PEM_DATA_COUNT"
        for (( x=0;x<$PEM_DATA_COUNT;x++ )); do
            CSV_LINE_PEM+="${PEM_DATA[${x}]},"
            MD_LINE_PEM+=" ${PEM_DATA[${x}]} |"
            if (( $(expr $x % 2 ) == 1 && ($x > 0) )); then
                echo $CSV_LINE_PEM >> certlist.csv
                echo $MD_LINE_PEM >> certlist.md
                if (( x < $PEM_DATA_COUNT-1 && ($x > 0) )); then
                    CSV_LINE_PEM="${PEM_ARRAY[${i}]},"
                    MD_LINE_PEM="| ${PEM_ARRAY[${i}]} |"
                fi
            fi
        done
    done

    # For each JKS file: extract name (subject) & expiry date (enddate) & build table
    echo " - Cert List mode => JKS"
    for (( i=0;i<$JKS_COUNT;i++)); do
        echo "JKS_file ${i}=${JKS_ARRAY[${i}]}"
        CSV_LINE_JKS="${JKS_ARRAY[${i}]},"
        MD_LINE_JKS="| ${JKS_ARRAY[${i}]} |"
        JKS_DATA=($(echo | keytool -v -list -keystore ${JKS_ARRAY[${i}]} 2>/dev/null | grep -i 'Alias name\|Valid' | sed -e 's/.*name: \(.*\)/\1/' | sed -e 's/.*until: \(.*\)/\1/'))
        JKS_DATA_COUNT=${#JKS_DATA[@]}
        echo "JKS DATA Count= $JKS_DATA_COUNT"
        for (( x=0;x<$JKS_DATA_COUNT;x++ )); do
            CSV_LINE_JKS+="${JKS_DATA[${x}]},"
            MD_LINE_JKS+=" ${JKS_DATA[${x}]} |"
            if (( $(expr $x % 2 ) == 1 && ($x > 0) )); then
                echo $CSV_LINE_JKS >> certlist.csv
                echo $MD_LINE_JKS >> certlist.md
                if (( x < $JKS_DATA_COUNT-1 && ($x > 0) )); then
                    CSV_LINE_JKS="${JKS_ARRAY[${i}]},"
                    MD_LINE_JKS="| ${JKS_ARRAY[${i}]} |"
                fi
            fi
        done
    done

    # echo "*** CERT TABLE ***"
    # cat certlist.csv
    # echo "MD"
    # cat certlist.md
fi

unset IFS
