#!/bin/bash
# Cert-Scanner.sh = Certificate scanner (.jks or .pem types) - List and/or Warn of expiring certs in a GitHub repo.
#   Can operate in 3 modes:
#     1) l = List: all private certs in a table
#     2) w = Warning: Find any expiring certs and notify via Jira ticket
#     3) b = Both List & Warning modes
#  Examples:
#    - list mode only => ./cert-scanner.sh -m l   # creates GH .md file & checks in (local .tsv to open in excel)
#    - warning mode   => ./cert-scanner.sh -m w -d 50 -j CCM   # warn if expires within 50 days and open Jira in CCM project
#    - warning mode   => ./cert-scanner.sh -m b -d 50 -j CCM

### Jira Creds (GH use Secret | local: set env var)
JIRA_USER="operzia" # Edit: Your Apptio alias
# JIRA_API_TOKEN= your Jira pwd - set in cmd window (not in code) Ex: export JIRA_API_TOKEN=abc123 then run script

### Jira Service account (jira.apptio.com only)
# JIRA_USER="svc_jira-admin"
# JIRA_API_TOKEN= ping operzia for token

### Date Expiry Function
# - Function params (required): 1) Cert name 2) Cert expiry date 3) Cert filename w/ path 4) Cert type (PEM or JKS)
# - Script param:
#   - $JIRA_PROJ = which Jira project to create ticket under (script param: -j <proj>)
#   - $DAYS = if cert expires with this number of days, create Jira ticket (script param: -d <int>)
cert_expiry_check() {
    #Param check
    echo "name= $1"
    echo "certExp= $2"
    echo "certFile= $3"
    echo "certType= $4"
    echo "jiraProj= $JIRA_PROJ"
    echo "daysExpire= $DAYS"

    #setup dates
    epoch_day=60*60*24 #sec*min*hour
    epoch_warn=$(( $DAYS*epoch_day ))
    # echo "epoch warn=$epoch_warn"

    today_epoch="$(date +%s)"
    # echo "today=$today_epoch"

    # expire_epoch=$(date +%s -d "$2") # Uncomment for LINUX (GH Runners)
    # BSD/MacOS VERSION of DATE (PEM & JKS need diff format conversion) - toggle off for Linux
    if [[ $4 = "PEM" ]]; then
      expire_epoch=$(date -j -f "%b %d %T %Y %Z" "$2" "+%s") 
    else
      expire_epoch=$(date -j -f "%a %b %d %T %Z %Y" "$2" "+%s")
    fi
    # echo "epoch=$expire_epoch"

    timeleft=`expr $expire_epoch - $today_epoch`
    daysleft=$(( timeleft/epoch_day ))
    echo "time_epoch= $timeleft => days_left= $daysleft"

    if [[ $timeleft -le $epoch_warn ]]; then
        CERT_WARN="WARNING = $3 expires $2 (in $daysleft days).  Certificate Name: $1"
        echo "****** $CERT_WARN ******"
        # Call Jira_Check function - Check if ticket already exists
        jira_check $3 $5

        # Only create Jira ticket if Jira_check sets BUG_EXISTS=0 (no open tickets for cert file)
        if [[ $BUG_EXISTS -eq 0 ]]; then
        #     echo '10.250.16.130 jira.apptio.com' | sudo tee -a /etc/hosts  # ONLY for GH runner (comment for local on VPN)
            SUMMARY="GH Cert Scan: Warning - Cert Expiring soon. File: $3"
            echo "sum= $SUMMARY"
            DATA='{"fields":{"project":{"key": "'$5'"},"summary":"'
            DATA+=${SUMMARY}
            DATA+='","description": "'
            DATA+=${CERT_WARN}
            DATA+='","issuetype": {"name": "Bug"}}}'
            echo "data= $DATA"
            curl -D- -u $JIRA_USER:$JIRA_API_TOKEN -X POST --data "$DATA" -H "Content-Type: application/json" https://jira-s.apptio.com/rest/api/2/issue/
        fi
    else
        echo "******* NO CERT EXPIRY DETECTED - Expires in $daysleft days ******"
    fi
}

### Check if Jira ticket exists
# - Jira Search:
#   - Project(team like TRON), Status ('open' or 'in progress'),
#   - Reporter (svc_jira-admin // service account), Summary contains Cert file
# - Returns: set env variable BUG_EXISTS (0 = no ticket exists)
jira_check() {
    #Param check
    echo "jSearch=$1"  # search Jira for Cert file
    echo "jProject=$2"

    echo "Starting: Jira search for existing tickets..."
    # Query Jira and extract data in response - pipe to .json file to 
    # JIRA (use srv accnt)
    # curl -D- -s -u $JIRA_USER:$JIRA_API_TOKEN -X GET -H "Content-Type: application/json" \
    # 'https://jira.apptio.com/rest/api/2/search?jql=project%20%3D%20'$1'%20AND%20status%20in%20(Open%2C%20"In%20Progress")%20AND%20text%20~%20"'$2'"%20AND%20reporter%20in%20(svc_jira-admin)&fields=id,key,summary' | grep "{" > tempJira.json

    # JIRA STAGE (jira-s) = Test env (access - use your account)
    curl -D- -u $JIRA_USER:$JIRA_API_TOKEN -X GET -H "Content-Type: application/json" \
    'https://jira-s.apptio.com/rest/api/2/search?jql=project%20%3D%20'$2'%20AND%20status%20in%20(Open%2C%20"In%20Progress")%20AND%20text%20~%20"'$1'"&fields=id,key,summary' | grep "{" > tempJira.json
    
    BUG_EXISTS=$(jq '.issues | length' tempJira.json)
    BUG_KEY=$(jq '.issues[0].key' tempJira.json)

    # echo "Bug_Exist=$BUG_EXISTS"
    # echo "Bug_Key=$BUG_KEY"

    if [[ $BUG_EXISTS -eq 0 ]]; then
        echo "No open bugs ($BUG_EXISTS found) - create ticket."
    else
        echo "Open bug found - $BUG_KEY - no ticket needed."
    fi
}

### Detect params to run
#   - mode: l=list only | w=warning only | b=both
#   - days: # of days before warning of expiring cert (only for warning | both mode)
#   - jira: jira project to open ticket for (only for warning | both mode)
while getopts "m:d:j:" options
do
    case "${options}"
        in
        m)MODE=${OPTARG};;
        d)DAYS=${OPTARG};;
        j)JIRA_PROJ=${OPTARG};;
    esac
done

echo "*** Cert Scanner: Settings ***"
echo " - Mode: $MODE"
if [[ $MODE = 'w' || $MODE = 'b' ]]; then
    echo " - Warning Time (days)  : $DAYS"
    echo " - Jira Project  : $JIRA_PROJ"
fi

# LOCAL CONFIG SECTION - control where scanner runs
# DEFAULT (cur dir) = Hack dir (BIIT) jks only # expired cert
# cd /Users/OPerzia/git2/apptio-bi/tron_gh/tron  #TRON (pem only)
# cd /Users/OPerzia/git2/ccm/cloud-service  #CCM (jks & pem)
# cd /Users/OPerzia/git2/apptio-bi/ssr/ssa-app  #SSA (2 pem)
cd /Users/OPerzia/git2/Shift
echo "Find certs under: " $PWD

IFS=$'\n'  # IFS: Allow splitting files found to be 1/line in array
# Find all .P12 variations & .JKS files in repo
JKS_ARRAY=($(find . -type f -name "*.jks" 2>/dev/null))
PEM_ARRAY=($(find . -type f \( -name "*.cer" -o -name "*.p12" -o -name "*.pfx" -o -name "*.pem" \) 2>/dev/null))

# Load Ignore Cert File Array
IGNORE_FILE_ARRAY=()
while IFS= read -r line; do
   IGNORE_FILE_ARRAY+=("$line")
done < <(grep "" "ignore_cert_file.txt")

IGNORE_FILE_COUNT=${#IGNORE_FILE_ARRAY[@]}
echo "cert_file_cnt=$IGNORE_FILE_COUNT"

# Load Ignore Cert Name Array
IGNORE_NAME_ARRAY=()
while IFS= read -r line; do
   IGNORE_NAME_ARRAY+=("$line")
done < <(grep "" "ignore_cert_name.txt")

IGNORE_NAME_COUNT=${#IGNORE_NAME_ARRAY[@]}
echo "cert_name_cnt=$IGNORE_NAME_COUNT"

# TEST search array
# SEARCH_STRING="dbrctrl_truststore"
# if [[ " ${CERT_ARRAY[*]} " == *"$SEARCH_STRING"* ]];
# then
#     echo "YES, your arr contains $SEARCH_STRING"
# else
#     echo "NO, your arr does not contain $SEARCH_STRING"
# fi

# get number of elements in the array
PEM_COUNT=${#PEM_ARRAY[@]}
echo ".PEM files= $PEM_COUNT"
JKS_COUNT=${#JKS_ARRAY[@]}
echo ".JKS files= $JKS_COUNT"

# WARNING MODE: Find certs expiring under X days from now
if [[ ($MODE = 'w' || $MODE = 'b') && $DAYS -gt 0 ]]; then
    echo "START - Cert Expiry mode"
    echo " - Start Cert Expiry => PEM"
    # For each PEM file: extract name (subject) & expiry date (enddate) & build table
    for (( i=0;i<$PEM_COUNT;i++ )); do
        # Check if cert file is to be ignored
        if [[ " ${IGNORE_FILE_ARRAY[*]} " == *"${PEM_ARRAY[${i}]}"* ]]; then
            echo "IGNORED ${i}: file array contains ${PEM_ARRAY[${i}]}"
        else
            PEM_DATA=($(openssl x509 -noout -subject -enddate -in ${PEM_ARRAY[${i}]} 2>/dev/null | sed -e 's/.*subject= \(.*\)/\1/' | sed -e 's/.*notAfter=\(.*\)/\1/' ))
            PEM_DATA_COUNT=${#PEM_DATA[@]}
            echo "PEM DATA Count= $PEM_DATA_COUNT"
            echo "Pem_Array= ${PEM_ARRAY[${i}]}"
            x=0
            while (( x < $PEM_DATA_COUNT )); do
                # Check if cert name is to be ignored
                if [[ " ${IGNORE_NAME_ARRAY[*]} " == *"${PEM_ARRAY[${i}]}"* ]]; then
                    echo "IGNORED ${x}: name array contains ${PEM_ARRAY[${i}]}"
                    (( x += 1 ))
                else
                    CERT_NAME_PEM=${PEM_DATA[${x}]}
                    (( x += 1 ))
                    CERT_EXPIRY=${PEM_DATA[${x}]}
                    cert_expiry_check $CERT_NAME_PEM $CERT_EXPIRY ${PEM_ARRAY[${i}]} PEM
                    (( x += 1 ))
                fi
            done
        fi
    done
    echo " END: Cert Expiry => PEM"

    # For each JKS file: extract name (subject) & expiry date (enddate) & build table
    echo " - Start Cert Expiry => JKS"
    for (( i=0;i<$JKS_COUNT;i++ )); do
        # Check if cert file is to be ignored
        if [[ " ${IGNORE_FILE_ARRAY[*]} " == *"${JKS_ARRAY[${i}]}"* ]]; then
            echo "IGNORED ${i}: file array contains ${JKS_ARRAY[${i}]}"
        else
            JKS_DATA=($(echo | keytool -v -list -keystore ${JKS_ARRAY[${i}]} 2>/dev/null | grep -i 'Alias name\|Valid' | sed -e 's/.*name: \(.*\)/\1/' | sed -e 's/.*until: \(.*\)/\1/'))
            JKS_DATA_COUNT=${#JKS_DATA[@]}
            echo "JKS DATA Count= $JKS_DATA_COUNT"
            x=0
            while (( x < $JKS_DATA_COUNT )); do
                # Check if cert name is to be ignored
                if [[ " ${IGNORE_NAME_ARRAY[*]} " == *"${JKS_DATA[${x}]}"* ]]; then
                    echo "IGNORED ${x}: name array contains ${JKS_DATA[${x}]}"
                    (( x += 1 ))
                else
                    CERT_NAME_JKS=${JKS_DATA[${x}]}
                    (( x += 1 ))
                    CERT_EXPIRY=${JKS_DATA[${x}]}
                    cert_expiry_check $CERT_NAME_JKS $CERT_EXPIRY ${JKS_ARRAY[${i}]} JKS
                    (( x += 1 ))
                fi
            done
        fi
    done
    echo " END: Cert Expiry => JKS"
    echo " END - Cert Expiry mode"
fi

### LIST MODE ###
if [[ $MODE = "l" || $MODE = "b" ]]; then
    echo "START - Cert List mode"
    # Create file and headers (tsv & md formats)
    echo -e "Path: Cert File\tCert Name\tExpiry Date" > certlist.tsv
    echo "| Path: Cert File | Cert Name | Expiry Date |" > certlist.md
    echo "| --------------- | --------- | ----------- |" >> certlist.md

    # For each PEM file: extract name (subject) & expiry date (enddate) & build table
    echo " - Cert List mode => PEM"
    for (( i=0;i<$PEM_COUNT;i++ )); do
        echo "PEM_file=${PEM_ARRAY[${i}]}"
        # Check if cert file is to be ignored
        if [[ " ${IGNORE_FILE_ARRAY[*]} " == *"${PEM_ARRAY[${i}]}"* ]]; then
            echo "IGNORED ${i}: file array contains ${PEM_ARRAY[${i}]}"
        else
            TSV_LINE_PEM="${PEM_ARRAY[${i}]}\t"
            MD_LINE_PEM="| ${PEM_ARRAY[${i}]} |"
            PEM_DATA=($(openssl x509 -noout -subject -enddate -in ${PEM_ARRAY[${i}]} 2>/dev/null | sed -e 's/.*subject= \(.*\)/\1/' | sed -e 's/.*notAfter=\(.*\)/\1/' ))
            PEM_DATA_COUNT=${#PEM_DATA[@]}
            echo "PEM DATA Count= $PEM_DATA_COUNT"
            for (( x=0;x<$PEM_DATA_COUNT;x++ )); do
                # Check if cert name is to be ignored
                if [[ " ${IGNORE_NAME_ARRAY[*]} " == *"${PEM_ARRAY[${i}]}"* ]]; then
                    echo "IGNORED ${x}: name array contains ${PEM_ARRAY[${i}]}"
                    (( x += 1 )) # Increment: skip expiry date too
                else
                    # Date conversion PEM: date -j -f "%b %d %T %Y %Z" "Jul  5 06:11:29 2022 GMT" "+%F %T %Z"
                    TSV_LINE_PEM+="${PEM_DATA[${x}]}\t"
                    MD_LINE_PEM+=" ${PEM_DATA[${x}]} |"
                    if (( $(expr $x % 2 ) == 1 && ($x > 0) )); then
                        echo -e $TSV_LINE_PEM >> certlist.tsv
                        echo $MD_LINE_PEM >> certlist.md
                        if (( x < $PEM_DATA_COUNT-1 && ($x > 0) )); then
                            TSV_LINE_PEM="${PEM_ARRAY[${i}]}\t"
                            MD_LINE_PEM="| ${PEM_ARRAY[${i}]} |"
                        fi
                    fi
                fi
            done
        fi
    done

    # For each JKS file: extract name (subject) & expiry date (enddate) & build table
    echo " - Cert List mode => JKS"
    for (( i=0;i<$JKS_COUNT;i++)); do
        echo "JKS_file ${i}=${JKS_ARRAY[${i}]}"
        # Check if cert file is to be ignored
        if [[ " ${IGNORE_FILE_ARRAY[*]} " == *"${JKS_ARRAY[${i}]}"* ]]; then
            echo "IGNORED ${i}: file array contains ${JKS_ARRAY[${i}]}"
        else
            # Date conversion JKS: date -j -f "%a %b %d %T %Z %Y" "Mon Dec 27 07:00:56 PST 2027" "+%F %T %Z"
            TSV_LINE_JKS="${JKS_ARRAY[${i}]}\t"
            MD_LINE_JKS="| ${JKS_ARRAY[${i}]} |"
            JKS_DATA=($(echo | keytool -v -list -keystore ${JKS_ARRAY[${i}]} 2>/dev/null | grep -i 'Alias name\|Valid' | sed -e 's/.*name: \(.*\)/\1/' | sed -e 's/.*until: \(.*\)/\1/'))
            JKS_DATA_COUNT=${#JKS_DATA[@]}
            echo "JKS DATA Count= $JKS_DATA_COUNT"
            for (( x=0;x<$JKS_DATA_COUNT;x++ )); do
                # Check if cert name is to be ignored
                if [[ " ${IGNORE_NAME_ARRAY[*]} " == *"${JKS_DATA[${x}]}"* ]]; then
                    echo "IGNORED ${x}: name array contains ${JKS_DATA[${x}]}"
                    (( x += 1 )) # Increment: skip expiry date too
                else
                    TSV_LINE_JKS+="${JKS_DATA[${x}]}\t"
                    MD_LINE_JKS+=" ${JKS_DATA[${x}]} |"
                    if (( $(expr $x % 2 ) == 1 && ($x > 0) )); then
                        echo -e $TSV_LINE_JKS >> certlist.tsv
                        echo $MD_LINE_JKS >> certlist.md
                        if (( x < $JKS_DATA_COUNT-1 && ($x > 0) )); then
                            TSV_LINE_JKS="${JKS_ARRAY[${i}]}\t"
                            MD_LINE_JKS="| ${JKS_ARRAY[${i}]} |"
                        fi
                    fi
                fi
            done
        fi
    done

    # echo "*** CERT TABLE ***"
    # cat certlist.tsv
    # echo "MD"
    # cat certlist.md

    echo "END - Cert List mode"
fi

unset IFS

echo "END - Cert Scanner"
