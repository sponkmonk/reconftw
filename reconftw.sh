#!/usr/bin/env bash

# Default config path
CONFIG_PATH="${RECONFTW_CFG}"

# Check if the config file exists
if [[ -f "${CONFIG_PATH}" ]]; then
    source "${CONFIG_PATH}"
else
    echo "Error: reconftw.cfg not found at ${CONFIG_PATH}!"
    exit 1
fi

# Welcome to reconFTW main script
#	 ██▀███  ▓█████  ▄████▄   ▒█████   ███▄    █   █████▒▄▄▄█████▓ █     █░
#	▓██ ▒ ██▒▓█   ▀ ▒██▀ ▀█  ▒██▒  ██▒ ██ ▀█   █ ▓██   ▒ ▓  ██▒ ▓▒▓█░ █ ░█░
#	▓██ ░▄█ ▒▒███   ▒▓█    ▄ ▒██░  ██▒▓██  ▀█ ██▒▒████ ░ ▒ ▓██░ ▒░▒█░ █ ░█
#	▒██▀▀█▄  ▒▓█  ▄ ▒▓▓▄ ▄██▒▒██   ██░▓██▒  ▐▌██▒░▓█▒  ░ ░ ▓██▓ ░ ░█░ █ ░█
#	░██▓ ▒██▒░▒████▒▒ ▓███▀ ░░ ████▓▒░▒██░   ▓██░░▒█░      ▒██▒ ░ ░░██▒██▓
#	░ ▒▓ ░▒▓░░░ ▒░ ░░ ░▒ ▒  ░░ ▒░▒░▒░ ░ ▒░   ▒ ▒  ▒ ░      ▒ ░░   ░ ▓░▒ ▒
#	  ░▒ ░ ▒░ ░ ░  ░  ░  ▒     ░ ▒ ▒░ ░ ░░   ░ ▒░ ░          ░      ▒ ░ ░
#	  ░░   ░    ░   ░        ░ ░ ░ ▒     ░   ░ ░  ░ ░      ░        ░   ░
#	   ░        ░  ░░ ░          ░ ░           ░                      ░
#
# 																by @six2dez

function banner_graber() {
    source "${SCRIPTPATH}"/banners.txt
    randx=$(shuf -i 1-23 -n 1)
    tmp="banner${randx}"
    banner_code=${!tmp}
    echo -e "${banner_code}"
}
function banner() {
    banner_code=$(banner_graber)
    printf "\n${bgreen}${banner_code}"
    printf "\n ${reconftw_version}                                 by @six2dez${reset}\n"
}

###############################################################################################################
################################################### TOOLS #####################################################
###############################################################################################################

rftw_util_version

###############################################################################################################
################################################### OSINT #####################################################
###############################################################################################################

function google_dorks() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $GOOGLE_DORKS == true ]] && [[ $OSINT == true ]]; then
        start_func "${FUNCNAME[0]}" "Searching interesting Google Dorks"
        spinny::start
        rftw_osint_googledorks -d "${DOMAIN}" -o ${dir}/osint/dorks.txt || {
            echo "rftw_osint_googledorks command failed"
            exit 1
        } 2>>"${LOGFILE}" >/dev/null 2>&1
        end_func "Results are saved in ${DOMAIN}/osint/dorks.txt" "${FUNCNAME[0]}"
    else
        if [[ $GOOGLE_DORKS == false ]] || [[ $OSINT == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} are already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function github_dorks() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $GITHUB_DORKS == true ]] && [[ $OSINT == true ]]; then
        start_func "${FUNCNAME[0]}" "Searching interesting GitHub Dorks"
        spinny::start
        rftw_osint_ghdorks -d "${DOMAIN}" -g "${GITHUB_TOKENS}" -o "${dir}/osint/gh_dorks.txt" || {
            echo -e "${bred}Error: rftw_osint_ghdorks command failed.${reset}" >&2
            exit 1
        }
        spinny::stop
        end_func "Results are saved in ${dir}/osint/gh_dorks.txt" "${FUNCNAME[0]}"
    else
        if [[ $GITHUB_DORKS == false ]] || [[ $OSINT == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} are already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function github_repos() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $GITHUB_REPOS == true ]] && [[ $OSINT == true ]]; then
        start_func "${FUNCNAME[0]}" "Github Repos analysis in process"
        spinny::start
        rftw_osint_ghrepos -d "${DOMAIN}" -t "${GITHUB_TOKENS}" -o osint/ghrepos.txt || {
            echo "rftw_osint_ghrepos command failed"
            exit 1
        } 2>>"${LOGFILE}" >/dev/null 2>&1
        spinny::stop
        end_func "Results are saved in ${DOMAIN}/osint/ghrepos.txt" "${FUNCNAME[0]}"
    else
        if [[ $GITHUB_REPOS == false ]] || [[ $OSINT == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function metadata() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $METADATA == true ]] && [[ $OSINT == true ]] && ! [[ ${DOMAIN} =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
        start_func "${FUNCNAME[0]}" "Metadata analysis in process"
        spinny::start
        rftw_osint_metadata -d "${DOMAIN}" -o "${dir}/osint" || {
            echo -e "${bred}Error: rftw_osint_metadata command failed.${reset}" >&2
            exit 1
        }
        spinny::stop
        end_func "Results are saved in ${DOMAIN}/osint/metadata.txt" "${FUNCNAME[0]}"
    else
        if [[ $METADATA == false ]] || [[ $OSINT == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed or input is an IP. To force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function postleaks() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $POSTLEAKS == true ]] && [[ $OSINT == true ]]; then
        start_func "${FUNCNAME[0]}" "Postleaks in process"
        spinny::start
        rftw_osint_postleaks -d "${DOMAIN}" -o "${dir}/osint/postleaks.txt" || {
            echo "rftw_osint_postleaks command failed"
            exit 1
        } 2>>"${LOGFILE}" >/dev/null 2>&1
        spinny::stop
        end_func "Results are saved in ${DOMAIN}/osint/postleaks.txt" "${FUNCNAME[0]}"
    else
        if [[ $POSTLEAKS == false ]] || [[ $OSINT == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function emails() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $EMAILS == true ]] && [[ $OSINT == true ]] && ! [[ ${DOMAIN} =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
        start_func "${FUNCNAME[0]}" "Emails search in process"
        spinny::start
        rftw_osint_emails -d "${DOMAIN}" -o "${dir}/osint/emails.txt" || {
            echo "rftw_osint_emails command failed"
            exit 1
        } 2>>"${LOGFILE}" >/dev/null 2>&1
        spinny::stop
        end_func "Results are saved in ${DOMAIN}/osint/emails.txt" "${FUNCNAME[0]}"
    else
        if [[ $EMAILS == false ]] || [[ $OSINT == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
    spinny::stop
}

function domain_info() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $DOMAIN_INFO == true ]] && [[ $OSINT == true ]] && ! [[ ${DOMAIN} =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
        start_func "${FUNCNAME[0]}" "Searching domain info (whois, registrant name/email domains)"
        spinny::start
        if [[ $DEEP == true ]]; then
            rftw_osint_whois -d "${DOMAIN}" --deep -o "${dir}/osint" || {
            echo "rftw_osint_whois command failed"
            exit 1
            } 2>>"${LOGFILE}" >/dev/null 2>&1
        else
            rftw_osint_whois -d "${DOMAIN}" -o "${dir}/osint" || {
            echo "rftw_osint_whois command failed"
            exit 1
            } 2>>"${LOGFILE}" >/dev/null 2>&1
        fi
        spinny::stop
        end_func "Results are saved in ${DOMAIN}/osint/domain_info_[general/name/email/ip].txt" "${FUNCNAME[0]}"
    else
        if [[ $DOMAIN_INFO == false ]] || [[ $OSINT == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
    spinny::stop
}

function ip_info() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $IP_INFO == true ]] && [[ $OSINT == true ]] && [[ ${DOMAIN} =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
        start_func ${FUNCNAME[0]} "Searching ip info"
        spinny::start
        if [[ -n $WHOISXML_API ]]; then
            curl "https://reverse-ip.whoisxmlapi.com/api/v1?apiKey=${WHOISXML_API}&ip=${DOMAIN}" 2>/dev/null | jq -r '.result[].name' 2>>"${LOGFILE}" | sed -e "s/$/ ${DOMAIN}/" | anew -q osint/ip_${DOMAIN}_relations.txt
            curl "https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${WHOISXML_API}&domainName=${DOMAIN}&outputFormat=json&da=2&registryRawText=1&registrarRawText=1&ignoreRawTexts=1" 2>/dev/null | jq 2>>"${LOGFILE}" | anew -q osint/ip_${DOMAIN}_whois.txt
            curl "https://ip-geolocation.whoisxmlapi.com/api/v1?apiKey=${WHOISXML_API}&ipAddress=${DOMAIN}" 2>/dev/null | jq -r '.ip,.location' 2>>"${LOGFILE}" | anew -q osint/ip_${DOMAIN}_location.txt
            end_func "Results are saved in ${DOMAIN}/osint/ip_[domain_relations|whois|location].txt" ${FUNCNAME[0]}
        else
            printf "\n${yellow} No WHOISXML_API var defined, skipping function ${reset}\n"
        fi
        spinny::stop
    else
        if [[ $IP_INFO == false ]] || [[ $OSINT == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        elif [[ ! ${DOMAIN} =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
            return
        else
            if [[ $IP_INFO == false ]] || [[ $OSINT == false ]]; then
                printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
            else
                printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
            fi
        fi
    fi
}

###############################################################################################################
############################################### SUBDOMAINS ####################################################
###############################################################################################################

function subdomains_full() {
	NUMOFLINES_subs="0"
	NUMOFLINES_probed="0"
	printf "${bgreen}#######################################################################\n\n"
	! [[ $DOMAIN =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]] && printf "${bblue} Subdomain Enumeration $DOMAIN\n\n"
	[[ $DOMAIN =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]] && printf "${bblue} Scanning IP $DOMAIN\n\n"
	[ -s "subdomains/subdomains.txt" ] && cp subdomains/subdomains.txt .tmp/subdomains_old.txt
	[ -s "webs/webs.txt" ] && cp webs/webs.txt .tmp/probed_old.txt

	if ([[ ! -f "$called_fn_dir/.sub_active" ]] || [[ ! -f "$called_fn_dir/.sub_brute" ]] || [[ ! -f "$called_fn_dir/.sub_permut" ]] || [[ ! -f "$called_fn_dir/.sub_recursive_brute" ]]) || [[ $DIFF == true ]]; then
		rftw_util_resolver
	fi

	[ -s "${inScope_file}" ] && cat ${inScope_file} | anew -q subdomains/subdomains.txt

	if ! [[ $DOMAIN =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]] && [[ $SUBDOMAINS_GENERAL == true ]]; then
		sub_passive
		sub_crt
		sub_active
		sub_noerror
		sub_brute
		sub_permut
		sub_regex_permut
		sub_recursive_passive
		sub_recursive_brute
		sub_dns
		sub_scraping
		sub_analytics
	else
		rftw_util_notification "IP/CIDR detected, subdomains search skipped" info
		echo $DOMAIN | anew -q subdomains/subdomains.txt
	fi

	rftw_web_screenshot
	if [[ -s "subdomains/subdomains.txt" ]]; then
		[ -s "$outOfScope_file" ] && rftw_util_deleteoos $outOfScope_file subdomains/subdomains.txt
		NUMOFLINES_subs=$(cat subdomains/subdomains.txt 2>>"$LOGFILE" | anew .tmp/subdomains_old.txt | sed '/^$/d' | wc -l)
	fi
	if [[ -s "webs/webs.txt" ]]; then
		[ -s "$outOfScope_file" ] && rftw_util_deleteoos $outOfScope_file webs/webs.txt
		NUMOFLINES_probed=$(cat webs/webs.txt 2>>"$LOGFILE" | anew .tmp/probed_old.txt | sed '/^$/d' | wc -l)
	fi
	printf "${bblue}\n Total subdomains: ${reset}\n\n"
	rftw_util_notification "- ${NUMOFLINES_subs} alive" good
	[ -s "subdomains/subdomains.txt" ] && cat subdomains/subdomains.txt | sort
	rftw_util_notification "- ${NUMOFLINES_probed} new web probed" good
	[ -s "webs/webs.txt" ] && cat webs/webs.txt | sort
	rftw_util_notification "Subdomain Enumeration Finished" good
	printf "${bblue} Results are saved in $DOMAIN/subdomains/subdomains.txt and webs/webs.txt${reset}\n"
	printf "${bgreen}#######################################################################\n\n"
}

function sub_passive() {
    if [[ ! -f "${called_fn_dir}/.sub_passive" ]] || [[ $DIFF == true ]] && [[ $SUBPASSIVE == true ]]; then
        start_subfunc ${FUNCNAME[0]} "Running : Passive Subdomain Enumeration"
        spinny::start
        rftw_sub_passive -d "${DOMAIN}" -a -s -g -l -o "${dir}/.tmp/subs_psub.txt" 2>>"${LOGFILE}"
        NUMOFLINES=$(find ${dir}/.tmp/ -type f -iname "*_psub.txt" -exec cat {} + | sed "s/*.//" | anew .tmp/passive_subs.txt | sed '/^$/d' | wc -l)
        spinny::stop
        end_subfunc "${NUMOFLINES} new subs (passive)" ${FUNCNAME[0]}
    else
        if [[ $SUBPASSIVE == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function sub_crt() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBCRT == true ]]; then
        start_subfunc ${FUNCNAME[0]} "Running : Crtsh Subdomain Enumeration"
        spinny::start
        rftw_sub_crt -d "${DOMAIN}" -o "${dir}/.tmp/crtsh_subs_tmp.txt" 2>>"${LOGFILE}"
        NUMOFLINES=$(cat .tmp/crtsh_subs_tmp.txt 2>>"${LOGFILE}" | sed 's/\*.//g' | anew .tmp/crtsh_subs.txt | sed '/^$/d' | wc -l)
        spinny::stop
        end_subfunc "${NUMOFLINES} new subs (cert transparency)" ${FUNCNAME[0]}
    else
        if [[ $SUBCRT == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function sub_active() {
    if [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; then
        start_subfunc ${FUNCNAME[0]} "Running : Active Subdomain Enumeration"
        spinny::start
        find .tmp -type f -iname "*_subs.txt" -exec cat {} + | anew -q .tmp/subs_no_resolved.txt
        [[ -s $outOfScope_file ]] && rftw_util_deleteoos $outOfScope_file .tmp/subs_no_resolved.txt
        rftw_sub_active -d "${DOMAIN}" -f ${dir}/.tmp/subs_no_resolved.txt -o "${dir}/.tmp/subdomains_active_tmp.txt"
        NUMOFLINES=$(cat .tmp/subdomains_active_tmp.txt 2>>"${LOGFILE}" | grep "\.$DOMAIN$\|^$DOMAIN$" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l)
        spinny::stop
        end_subfunc "${NUMOFLINES} subs DNS resolved from passive" ${FUNCNAME[0]}
    else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
    fi
}

function sub_noerror() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBNOERROR == true ]]; then
        start_subfunc ${FUNCNAME[0]} "Running : Checking NOERROR DNS response"
        spinny::start
        resolvers_update_quick_local
        rftw_sub_noerror -d "${DOMAIN}" -o .tmp/subs_noerror_ok.txt
        NUMOFLINES=$(cat .tmp/subs_noerror_ok.txt 2>>"${LOGFILE}" | sed "s/*.//" | grep ".$DOMAIN$" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l)
        spinny::stop
        end_subfunc "${NUMOFLINES} new subs (DNS noerror)" ${FUNCNAME[0]}
    else
        if [[ $SUBBRUTE == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function sub_dns() {
    if [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; then
        start_subfunc ${FUNCNAME[0]} "Running : DNS Subdomain Enumeration and PTR search"
        spinny::start
        rftw_sub_dns -f subdomains/subdomains.txt -o ${dir}/.tmp/subdomains_dns_okresolved.txt
        cp .tmp/subdomains_dnsregs.json subdomains/subdomains_dnsregs.json 2>>"${LOGFILE}"
        [[ ${INSCOPE} == true ]] && check_inscope .tmp/subdomains_dns_okresolved.txt 2>>"${LOGFILE}" >/dev/null
        NUMOFLINES=$(cat .tmp/subdomains_dns_okresolved.txt 2>>"${LOGFILE}" | grep "\.$DOMAIN$\|^$DOMAIN$" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l)
        spinny::stop
        end_subfunc "${NUMOFLINES} new subs (dns resolution)" ${FUNCNAME[0]}
    else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
    fi
}

function sub_brute() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBBRUTE == true ]]; then
        start_subfunc ${FUNCNAME[0]} "Running : Bruteforce Subdomain Enumeration"
        spinny::start
        rftw_sub_brute -d "${DOMAIN}" -o ${dir}/.tmp/subs_brute_valid.txt
        [[ ${INSCOPE} == true ]] && check_inscope .tmp/subs_brute_valid.txt 2>>"${LOGFILE}" >/dev/null
        NUMOFLINES=$(cat .tmp/subs_brute_valid.txt 2>>"${LOGFILE}" | sed "s/*.//" | grep ".$DOMAIN$" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l)
        spinny::stop
        end_subfunc "${NUMOFLINES} new subs (bruteforce)" ${FUNCNAME[0]}
    else
        if [[ $SUBBRUTE == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function sub_scraping() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBSCRAPING == true ]]; then
        start_subfunc ${FUNCNAME[0]} "Running : Source code scraping subdomain search"
        spinny::start
        if [[ -s "${dir}/subdomains/subdomains.txt" ]]; then
            if [[ $(cat subdomains/subdomains.txt | wc -l) -le $DEEP_LIMIT ]] || [[ $DEEP == true ]]; then
                if [[ ! ${AXIOM} == true ]]; then
                    if [[ ${DEEP} == true ]]; then
                        rftw_sub_scraipng -f ${dir}/subdomains/subdomains.txt -o ${dir}/.tmp/scrap_subs_resolved.txt --deep
                    else
                        rftw_sub_scraipng -f ${dir}/subdomains/subdomains.txt -o ${dir}/.tmp/scrap_subs_resolved.txt
                    fi
                else
                    if [[ ${DEEP} == true ]]; then
                        rftw_sub_scraipng -f ${dir}/subdomains/subdomains.txt -o ${dir}/.tmp/scrap_subs_resolved.txt --no-axiom --deep
                    else
                        rftw_sub_scraipng -f ${dir}/subdomains/subdomains.txt -o ${dir}/.tmp/scrap_subs_resolved.txt --no-axiom
                    fi
                fi
                if [[ ${INSCOPE} == true ]]; then
                    check_inscope .tmp/scrap_subs_resolved.txt 2>>"${LOGFILE}" >/dev/null
                fi
                NUMOFLINES=$(cat .tmp/scrap_subs_resolved.txt 2>>"${LOGFILE}" | grep "\.$DOMAIN$\|^$DOMAIN$" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | anew subdomains/subdomains.txt | tee .tmp/diff_scrap.txt | sed '/^$/d' | wc -l)
                [[ -s ".tmp/diff_scrap.txt" ]] && cat .tmp/diff_scrap.txt | httpx -follow-host-redirects -random-agent -status-code -threads $HTTPX_THREADS -rl $HTTPX_RATELIMIT -timeout $HTTPX_TIMEOUT -silent -retries 2 -title -web-server -tech-detect -location -no-color -json -o .tmp/web_full_info3.txt 2>>"${LOGFILE}" >/dev/null
                [[ -s ".tmp/web_full_info3.txt" ]] && cat .tmp/web_full_info3.txt | jq -r 'try .url' 2>/dev/null | grep "${DOMAIN}" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | sed "s/*.//" | anew .tmp/probed_tmp_scrap.txt | unfurl -u domains 2>>"${LOGFILE}" | anew -q .tmp/scrap_subs.txt
                cat .tmp/web_full_info1.txt .tmp/web_full_info2.txt .tmp/web_full_info3.txt 2>>"${LOGFILE}" | jq -s 'try .' | jq 'try unique_by(.input)' | jq 'try .[]' 2>>"${LOGFILE}" >.tmp/web_full_info.txt
                end_subfunc "${NUMOFLINES} new subs (code scraping)" ${FUNCNAME[0]}
            else
                end_subfunc "Skipping Subdomains Web Scraping: Too Many Subdomains" ${FUNCNAME[0]}
            fi
        else
            end_subfunc "No subdomains to search (code scraping)" ${FUNCNAME[0]}
        fi
        spinny::stop
    else
        if [[ $SUBSCRAPING == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function sub_analytics() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBANALYTICS == true ]]; then
        start_subfunc ${FUNCNAME[0]} "Running : Analytics Subdomain Enumeration"
        spinny::start
        rftw_sub_analytics -i ${dir}/.tmp/probed_tmp_scrap.txt -o ${dir}/.tmp/analytics_subs_resolved.txt
        [[ ${INSCOPE} == true ]] && check_inscope .tmp/analytics_subs_resolved.txt 2>>"${LOGFILE}" >/dev/null
        NUMOFLINES=$(cat .tmp/analytics_subs_resolved.txt 2>>"${LOGFILE}" | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l)
        spinny::stop
        end_subfunc "${NUMOFLINES} new subs (analytics relationship)" ${FUNCNAME[0]}
    else
        if [[ $SUBANALYTICS == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function sub_permut() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBPERMUTE == true ]]; then
        start_subfunc ${FUNCNAME[0]} "Running : Permutations Subdomain Enumeration"
        spinny::start
        rftw_sub_permute -f ${dir}/subdomains/subdomains.txt -o "${dir}/.tmp/permute_subs.txt"
        if [[ -s ".tmp/permute_subs.txt" ]]; then
            [[ -s $outOfScope_file ]] && rftw_util_deleteoos $outOfScope_file .tmp/permute_subs.txt
            [[ ${INSCOPE} == true ]] && check_inscope .tmp/permute_subs.txt 2>>"${LOGFILE}" >/dev/null
            NUMOFLINES=$(cat .tmp/permute_subs.txt 2>>"${LOGFILE}" | grep ".$DOMAIN$" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l)
        else
            NUMOFLINES=0
        fi
        spinny::stop
        end_subfunc "${NUMOFLINES} new subs (permutations)" ${FUNCNAME[0]}
    else
        if [[ $SUBPERMUTE == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function sub_regex_permut() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBREGEXPERMUTE == true ]]; then
        start_subfunc ${FUNCNAME[0]} "Running : Permutations by regex analysis"
        spinny::start
        rftw_sub_regex -d "${DOMAIN}" -f ${dir}/subdomains/subdomains.txt -o "${dir}/.tmp/regulator.txt"
        if [[ -s ".tmp/regulator.txt" ]]; then
            [[ -s $outOfScope_file ]] && rftw_util_deleteoos $outOfScope_file .tmp/regulator.txt
            [[ ${INSCOPE} == true ]] && check_inscope .tmp/regulator.txt 2>>"${LOGFILE}" >/dev/null
            NUMOFLINES=$(cat .tmp/regulator.txt 2>>"${LOGFILE}" | grep ".$DOMAIN$" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l)
        else
            NUMOFLINES=0
        fi
        spinny::stop
        end_subfunc "${NUMOFLINES} new subs (permutations by regex)" ${FUNCNAME[0]}
    else
        if [[ $SUBREGEXPERMUTE == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function sub_recursive_passive() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUB_RECURSIVE_PASSIVE == true ]] && [[ -s "subdomains/subdomains.txt" ]]; then
        start_subfunc ${FUNCNAME[0]} "Running : Subdomains recursive search passive"
        spinny::start
        # Passive recursive
        rftw_sub_recpassive -d ${DOMAIN} -f ${dir}/subdomains/subdomains.txt -o ${dir}/.tmp/brute_perm_recursive_final.txt
        [[ ${INSCOPE} == true ]] && check_inscope .tmp/passive_recurs_tmp.txt 2>>"${LOGFILE}" >/dev/null
        NUMOFLINES=$(cat .tmp/passive_recurs_tmp.txt 2>>"${LOGFILE}" | grep "\.$DOMAIN$\|^$DOMAIN$" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | sed '/^$/d' | anew subdomains/subdomains.txt | wc -l)
        spinny::stop
        end_subfunc "${NUMOFLINES} new subs (recursive)" ${FUNCNAME[0]}
    else
        if [[ $SUB_RECURSIVE_PASSIVE == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function sub_recursive_brute() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUB_RECURSIVE_BRUTE == true ]] && [[ -s "subdomains/subdomains.txt" ]]; then
        start_subfunc ${FUNCNAME[0]} "Running : Subdomains recursive search active"
        spinny::start
        rftw_sub_recbrute -d ${DOMAIN} -f ${dir}/subdomains/subdomains.txt -o ${dir}/.tmp/brute_perm_recursive_final.txt
        NUMOFLINES=$(cat .tmp/brute_perm_recursive_final.txt 2>>"${LOGFILE}" | grep "\.$DOMAIN$\|^$DOMAIN$" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | sed '/^$/d' | anew subdomains/subdomains.txt | wc -l)
        end_subfunc "${NUMOFLINES} new subs (recursive active)" ${FUNCNAME[0]}
        spinny::stop
    else
        if [[ $SUB_RECURSIVE_BRUTE == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function subtakeover() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBTAKEOVER == true ]]; then
        start_func ${FUNCNAME[0]} "Looking for possible subdomain and DNS takeover"
        spinny::start
        touch .tmp/tko.txt
        [[ ! -s ".tmp/webs_all.txt" ]] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q .tmp/webs_all.txt
        cat subdomains/subdomains.txt .tmp/webs_all.txt 2>/dev/null | anew -q .tmp/input_takeover.txt

        rftw_sub_takeover -d ${DOMAIN} -f ${dir}/.tmp/input_takeover.txt -o ${dir}/.tmp/tko.txt

        NUMOFLINES=$(cat .tmp/tko.txt 2>>"${LOGFILE}" | anew webs/takeover.txt | sed '/^$/d' | wc -l)
        if [[ $NUMOFLINES -gt 0 ]]; then
            rftw_util_notification "${NUMOFLINES} new possible takeovers found" info
        fi
        spinny::stop
        end_func "Results are saved in ${DOMAIN}/webs/takeover.txt" ${FUNCNAME[0]}
    else
        if [[ $SUBTAKEOVER == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function zonetransfer() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $ZONETRANSFER == true ]] && ! [[ ${DOMAIN} =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
        start_func ${FUNCNAME[0]} "Zone transfer check"
        spinny::start
        for ns in $(dig +short ns "${DOMAIN}"); do dig axfr "${DOMAIN}" @"$ns" >>subdomains/zonetransfer.txt; done
        if [[ -s "subdomains/zonetransfer.txt" ]]; then
            if ! grep -q "Transfer failed" subdomains/zonetransfer.txt; then rftw_util_notification "Zone transfer found on ${DOMAIN}!" info; fi
        fi
        spinny::stop
        end_func "Results are saved in${DOMAIN}/subdomains/zonetransfer.txt" ${FUNCNAME[0]}
    else
        if [[ $ZONETRANSFER == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        elif [[ ${DOMAIN} =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
            return
        else
            if [[ $ZONETRANSFER == false ]]; then
                printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
            else
                printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
            fi
        fi
    fi
}

function s3buckets() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $S3BUCKETS == true ]] && ! [[ ${DOMAIN} =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
        start_func ${FUNCNAME[0]} "AWS S3 buckets search"
        spinny::start
        # S3Scanner
        rftw_sub_s3buckets -d ${DOMAIN} -f ${dir}/subdomains/subdomains.txt -o ${dir}/.tmp

        NUMOFLINES1=$(cat .tmp/output_cloud.txt 2>>"${LOGFILE}" | sed '/^#/d' | sed '/^$/d' | anew subdomains/cloud_assets.txt | wc -l)
        if [[ $NUMOFLINES1 -gt 0 ]]; then
            rftw_util_notification "${NUMOFLINES1} new cloud assets found" info
        fi
        NUMOFLINES2=$(cat .tmp/s3buckets.txt 2>>"${LOGFILE}" | grep -aiv "not_exist" | grep -aiv "Warning:" | grep -aiv "invalid_name" | grep -aiv "^http" | awk 'NF' | anew subdomains/s3buckets.txt | sed '/^$/d' | wc -l)
        if [[ $NUMOFLINES2 -gt 0 ]]; then
            rftw_util_notification "${NUMOFLINES2} new S3 buckets found" info
        fi
        spinny::stop
        end_func "Results are saved in subdomains/s3buckets.txt and subdomains/cloud_assets.txt" ${FUNCNAME[0]}
    else
        if [[ $S3BUCKETS == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        elif [[ ${DOMAIN} =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
            return
        else
            if [[ $S3BUCKETS == false ]]; then
                printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
            else
                printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
            fi
        fi
    fi
}

###############################################################################################################
########################################### WEB DETECTION #####################################################
###############################################################################################################

function webprobe_simple() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $WEBPROBESIMPLE == true ]]; then
        start_subfunc ${FUNCNAME[0]} "Running : Http probing${DOMAIN}/"
        spinny::start
        rftw_web_probecommon -f ${DOMAIN_FILE} -o .tmp/web_full_info1.txt
        cat .tmp/web_full_info.txt .tmp/web_full_info_probe.txt webs/web_full_info.txt 2>>"${LOGFILE}" | jq -s 'try .' | jq 'try unique_by(.input)' | jq 'try .[]' 2>>"${LOGFILE}" >webs/web_full_info.txt
        [[ -s "webs/web_full_info.txt" ]] && cat webs/web_full_info.txt | jq -r 'try .url' 2>/dev/null | grep "${DOMAIN}" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | sed "s/*.//" | anew -q .tmp/probed_tmp.txt
        [[ -s "webs/web_full_info.txt" ]] && cat webs/web_full_info.txt | jq -r 'try . |"\(.url) [\(.status_code)] [\(.title)] [\(.webserver)] \(.tech)"' | grep "${DOMAIN}" | anew -q webs/web_full_info_plain.txt
        [[ -s $outOfScope_file ]] && rftw_util_deleteoos $outOfScope_file .tmp/probed_tmp.txt
        NUMOFLINES=$(cat .tmp/probed_tmp.txt 2>>"${LOGFILE}" | anew webs/webs.txt | sed '/^$/d' | wc -l)
        cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q .tmp/webs_all.txt
        spinny::stop
        end_subfunc "${NUMOFLINES} new websites resolved" ${FUNCNAME[0]}
        if [[ $PROXY == true ]] && [[ -n $proxy_url ]] && [[ $(cat webs/webs.txt | wc -l) -le $DEEP_LIMIT2 ]]; then
            rftw_util_notification "Sending websites to proxy" info
            ffuf -mc all -w webs/webs.txt -u FUZZ -replay-proxy $proxy_url 2>>"${LOGFILE}" >/dev/null
        fi
    else
        if [[ $WEBPROBESIMPLE == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function webprobe_full() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $WEBPROBEFULL == true ]]; then
        start_func ${FUNCNAME[0]} "Http probing non standard ports"
        spinny::start
        rftw_web_probecommon -f ${dir}/subdomains/subdomains.txt -o ${dir}/.tmp/web_full_info_uncommon.txt
        [[ -s ".tmp/web_full_info_uncommon.txt" ]] && cat .tmp/web_full_info_uncommon.txt | jq -r 'try .url' 2>/dev/null | grep "${DOMAIN}" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | sed "s/*.//" | anew -q .tmp/probed_uncommon_ports_tmp.txt
        [[ -s ".tmp/web_full_info_uncommon.txt" ]] && cat .tmp/web_full_info_uncommon.txt | jq -r 'try . |"\(.url) [\(.status_code)] [\(.title)] [\(.webserver)] \(.tech)"' | anew -q webs/web_full_info_uncommon_plain.txt
        if [[ -s ".tmp/web_full_info_uncommon.txt" ]]; then
            if [[ ${DOMAIN} =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
                cat .tmp/web_full_info_uncommon.txt 2>>"${LOGFILE}" | anew -q webs/web_full_info_uncommon.txt
            else
                cat .tmp/web_full_info_uncommon.txt 2>>"${LOGFILE}" | grep "${DOMAIN}" | anew -q webs/web_full_info_uncommon.txt
            fi
        fi
        NUMOFLINES=$(cat .tmp/probed_uncommon_ports_tmp.txt 2>>"${LOGFILE}" | anew webs/webs_uncommon_ports.txt | sed '/^$/d' | wc -l)
        rftw_util_notification "Uncommon web ports: ${NUMOFLINES} new websites" good
        [[ -s "webs/webs_uncommon_ports.txt" ]] && cat webs/webs_uncommon_ports.txt
        cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q .tmp/webs_all.txt
        spinny::stop
        end_func "Results are saved in ${DOMAIN}/webs/webs_uncommon_ports.txt" ${FUNCNAME[0]}
        if [[ $PROXY == true ]] && [[ -n $proxy_url ]] && [[ $(cat webs/webs_uncommon_ports.txt | wc -l) -le $DEEP_LIMIT2 ]]; then
            rftw_util_notification "Sending websites with uncommon ports to proxy" info
            ffuf -mc all -w webs/webs_uncommon_ports.txt -u FUZZ -replay-proxy $proxy_url 2>>"${LOGFILE}" >/dev/null
        fi
    else
        if [[ $WEBPROBEFULL == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function screenshot() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $WEBSCREENSHOT == true ]]; then
        start_func ${FUNCNAME[0]} "Web Screenshots"
        spinny::start
        [[ ! -s ".tmp/webs_all.txt" ]] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q .tmp/webs_all.txt
        rftw_web_probecommon -f ${dir}/.tmp/webs_all.txt -o ${dir}/webs/screenshots
        spinny::stop
        end_func "Results are saved in ${DOMAIN}/screenshots folder" ${FUNCNAME[0]}
    else
        if [[ $WEBSCREENSHOT == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function virtualhosts() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $VIRTUALHOSTS == true ]]; then
        start_func ${FUNCNAME[0]} "Virtual Hosts dicovery"
        spinny::start
        [[ ! -s ".tmp/webs_all.txt" ]] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q .tmp/webs_all.txt
        if [[ -s ".tmp/webs_all.txt" ]]; then
            rftw_web_vhosts -f ${dir}/.tmp/webs_all.txt -o ${dir}/virtualhosts
            end_func "Results are saved in ${DOMAIN}/virtualhosts/*subdomain*.txt" ${FUNCNAME[0]}
        else
            end_func "No${DOMAIN}//web/webs.txts file found, virtualhosts skipped " ${FUNCNAME[0]}
        fi
        spinny::stop
    else
        if [[ $VIRTUALHOSTS == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

###############################################################################################################
############################################# HOST SCAN #######################################################
###############################################################################################################

function favicon() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $FAVICON == true ]] && ! [[ ${DOMAIN} =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
        start_func ${FUNCNAME[0]} "Favicon Ip Lookup"
        spinny::start
        rftw_ip_favicon -d ${DOMAIN} -o ${dir}/hosts/favicontest.txt
        spinny::stop
        end_func "Results are saved in hosts/favicontest.txt" ${FUNCNAME[0]}
    else
        if [[ $FAVICON == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        elif [[ ${DOMAIN} =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
            return
        else
            if [[ $FAVICON == false ]]; then
                printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
            else
                printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
            fi
        fi
    fi
}

function portscan() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $PORTSCANNER == true ]]; then
        start_func ${FUNCNAME[0]} "Port scan"
        spinny::start
        if ! [[ ${DOMAIN} =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
            [[ -s "subdomains/subdomains_dnsregs.json" ]] && cat subdomains/subdomains_dnsregs.json | jq -r 'try . | "\(.host) \(.a[0])"' | anew -q .tmp/subs_ips.txt
            [[ -s ".tmp/subs_ips.txt" ]] && awk '{ print $2 " " $1}' .tmp/subs_ips.txt | sort -k2 -n | anew -q hosts/subs_ips_vhosts.txt
            [[ -s "hosts/subs_ips_vhosts.txt" ]] && cat hosts/subs_ips_vhosts.txt | cut -d ' ' -f1 | grep -aEiv "^(127|10|169\.154|172\.1[6789]|172\.2[0-9]|172\.3[01]|192\.168)\." | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | anew -q hosts/ips.txt
        else
            echo "${DOMAIN}" | grep -aEiv "^(127|10|169\.154|172\.1[6789]|172\.2[0-9]|172\.3[01]|192\.168)\." | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | anew -q hosts/ips.txt
        fi

        rftw_ip_portscan -f ${dir}/hosts/ips.txt -o ${dir}/hosts

        spinny::stop
        end_func "Results are saved in hosts/portscan_[passive|active].txt" ${FUNCNAME[0]}
    else
        if [[ $PORTSCANNER == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function cdnprovider() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $CDN_IP == true ]]; then
        start_func ${FUNCNAME[0]} "CDN provider check"
        spinny::start
        [[ -s "subdomains/subdomains_dnsregs.json" ]] && cat subdomains/subdomains_dnsregs.json | jq -r 'try . | .a[]' | grep -aEiv "^(127|10|169\.154|172\.1[6789]|172\.2[0-9]|172\.3[01]|192\.168)\." | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort -u >.tmp/ips_cdn.txt
        [[ -s ".tmp/ips_cdn.txt" ]] && cat .tmp/ips_cdn.txt | rftw_ip_cdnprovider | anew -q "${dir}"/hosts/cdn_providers.txt
        spinny::stop
        end_func "Results are saved in hosts/cdn_providers.txt" ${FUNCNAME[0]}
    else
        if [[ $CDN_IP == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

###############################################################################################################
############################################# WEB SCAN ########################################################
###############################################################################################################

function waf_checks() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $WAF_DETECTION == true ]]; then
        start_func ${FUNCNAME[0]} "Website's WAF detection"
        spinny::start
        [[ ! -s ".tmp/webs_all.txt" ]] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q .tmp/webs_all.txt
        if [[ -s ".tmp/webs_all.txt" ]]; then
            rftw_web_wafchecks -f ${dir}/.tmp/webs_all.txt -o ${dir}/webs/webs_wafs.txt
            if [[ -s "webs/webs_wafs.txt" ]]; then
                NUMOFLINES=$(cat webs/webs_wafs.txt 2>>"${LOGFILE}" | sed '/^$/d' | wc -l)
                rftw_util_notification "${NUMOFLINES} websites protected by waf" info
                end_func "Results are saved in ${DOMAIN}/webs/webs_wafs.txt" ${FUNCNAME[0]}
            else
                end_func "No results found" ${FUNCNAME[0]}
            fi
        else
            end_func "No websites to scan" ${FUNCNAME[0]}
        fi
        spinny::stop
    else
        if [[ $WAF_DETECTION == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function nuclei_check() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $NUCLEICHECK == true ]]; then
        start_func ${FUNCNAME[0]} "Templates based web scanner"

        spinny::start

        nuclei -update 2>>"${LOGFILE}" >/dev/null
        mkdir -p nuclei_output
        [[ ! -s ".tmp/webs_all.txt" ]] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q .tmp/webs_all.txt
        [[ ! -s ".tmp/webs_subs.txt" ]] && cat subdomains/subdomains.txt .tmp/webs_all.txt 2>>"${LOGFILE}" | anew -q .tmp/webs_subs.txt

        rftw_web_nucleichecks -f ${dir}/.tmp/webs_subs.txt -o ${dir}/nuclei_output

        spinny::stop

        end_func "Results are saved in ${DOMAIN}/nuclei_output folder" ${FUNCNAME[0]}
    else
        if [[ $NUCLEICHECK == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function fuzz() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $FUZZ == true ]]; then
        start_func ${FUNCNAME[0]} "Web directory fuzzing"
        spinny::start
        [[ ! -s ".tmp/webs_all.txt" ]] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q .tmp/webs_all.txt
        if [[ -s ".tmp/webs_all.txt" ]]; then

            rftw_web_fuzz -f ${dir}/.tmp/webs_all.txt -o ${dir}/fuzzing

            end_func "Results are saved in ${DOMAIN}/fuzzing/*subdomain*.txt" ${FUNCNAME[0]}
        else
            end_func "No${DOMAIN}//web/webs.txts file found, fuzzing skipped " ${FUNCNAME[0]}
        fi
        spinny::stop
    else
        if [[ $FUZZ == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function cms_scanner() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $CMS_SCANNER == true ]]; then
        mkdir -p "${dir}"/cms && rm -rf "${dir}"/cms/*
        [[ ! -s ".tmp/webs_all.txt" ]] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q .tmp/webs_all.txt
        if [[ -s ".tmp/webs_all.txt" ]]; then
            start_func ${FUNCNAME[0]} "CMS Scanner"
            spinny::start
            rftw_web_cms -f ${dir}/.tmp/webs_all.txt -o "${dir}"/cms/
            spinny::stop
            end_func "Results are saved in ${DOMAIN}/cms/*subdomain* folder" ${FUNCNAME[0]}
        else
            end_func "No${DOMAIN}//web/webs.txts file found, cms scanner skipped" ${FUNCNAME[0]}
        fi
    else
        if [[ $CMS_SCANNER == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function urlchecks() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $URL_CHECK == true ]]; then
        mkdir -p js
        [[ ! -s ".tmp/webs_all.txt" ]] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q .tmp/webs_all.txt
        if [[ -s ".tmp/webs_all.txt" ]]; then

            start_func ${FUNCNAME[0]} "URL Extraction"

            spinny::start

            rftw_web_urlchecks -f .tmp/webs_all.txt -o ${dir}/.tmp

            NUMOFLINES=$(cat .tmp/url_extract_uddup.txt 2>>"${LOGFILE}" | anew webs/url_extract.txt | sed '/^$/d' | wc -l)
            rftw_util_notification "${NUMOFLINES} new urls with params" info

            spinny::stop

            end_func "Results are saved in ${DOMAIN}/webs/url_extract.txt" ${FUNCNAME[0]}
            if [[ $PROXY == true ]] && [[ -n $proxy_url ]] && [[ $(cat webs/url_extract.txt | wc -l) -le $DEEP_LIMIT2 ]]; then
                rftw_util_notification "Sending urls to proxy" info
                ffuf -mc all -w webs/url_extract.txt -u FUZZ -replay-proxy $proxy_url 2>>"${LOGFILE}" >/dev/null
            fi
        fi
    else
        if [[ $URL_CHECK == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function url_gf() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $URL_GF == true ]]; then
        start_func ${FUNCNAME[0]} "Vulnerable Pattern Search"

        spinny::start
        rftw_web_urlgf -f .tmp/webs_all.txt -o ${dir}/gf
        spinny::stop

        end_func "Results are saved in ${DOMAIN}/gf folder" ${FUNCNAME[0]}
    else
        if [[ $URL_GF == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function url_ext() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $URL_EXT == true ]]; then
        if [[ -s ".tmp/url_extract_tmp.txt" ]]; then
            start_func ${FUNCNAME[0]} "Urls by extension"
            spinny::start

            rftw_web_urlext -f .tmp/webs_all.txt -o ${dir}/.tmp

            spinny::stop
            end_func "Results are saved in ${DOMAIN}/webs/urls_by_ext.txt" ${FUNCNAME[0]}
        fi
    else
        if [[ $URL_EXT == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function jschecks() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $JSCHECKS == true ]]; then
        start_func ${FUNCNAME[0]} "Javascript Scan"
        if [[ -s ".tmp/url_extract_js.txt" ]]; then
            spinny::start

            rftw_web_jschecks -f .tmp/url_extract_js.txt -o ${dir}/js

            spinny::stop
            end_func "Results are saved in ${DOMAIN}/js folder" ${FUNCNAME[0]}
        else
            end_func "No JS urls found for${DOMAIN}/, function skipped" ${FUNCNAME[0]}
        fi
    else
        if [[ $JSCHECKS == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function wordlist_gen() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $WORDLIST == true ]]; then
        start_func ${FUNCNAME[0]} "Wordlist generation"

        spinny::start

        rftw_web_wordlists -f .tmp/url_extract_js.txt -o ${dir}/web

        spinny::stop

        end_func "Results are saved in ${DOMAIN}/webs/dict_[words|paths].txt" ${FUNCNAME[0]}
        if [[ $PROXY == true ]] && [[ -n $proxy_url ]] && [[ $(cat webs/all_paths.txt | wc -l) -le $DEEP_LIMIT2 ]]; then
            rftw_util_notification "Sending urls to proxy" info
            ffuf -mc all -w webs/all_paths.txt -u FUZZ -replay-proxy $proxy_url 2>>"${LOGFILE}" >/dev/null
        fi
    else
        if [[ $WORDLIST == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function wordlist_gen_roboxtractor() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $ROBOTSWORDLIST == true ]]; then
        start_func ${FUNCNAME[0]} "Robots wordlist generation"
        [[ ! -s ".tmp/webs_all.txt" ]] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q .tmp/webs_all.txt
        spinny::start

        rftw_web_roboxtractor -f .tmp/webs_all.txt -o ${dir}/web

        spinny::stop
        end_func "Results are saved in ${DOMAIN}/webs/robots_wordlist.txt" ${FUNCNAME[0]}
    else
        if [[ $ROBOTSWORDLIST == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function password_dict() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $PASSWORD_DICT == true ]]; then
        start_func ${FUNCNAME[0]} "Password dictionary generation"

        spinny::start

        rftw_web_passdict -d $DOMAIN -o ${dir}/web

        spinny::stop

        end_func "Results are saved in ${DOMAIN}/webs/password_dict.txt" ${FUNCNAME[0]}
    else
        if [[ $PASSWORD_DICT == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

###############################################################################################################
######################################### VULNERABILITIES #####################################################
###############################################################################################################

function brokenLinks() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $BROKENLINKS == true ]]; then
        start_func ${FUNCNAME[0]} "Broken links checks"
        [[ ! -s ".tmp/webs_all.txt" ]] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q .tmp/webs_all.txt
        spinny::start

        rftw_vuln_brokenlink -f .tmp/webs_all.txt -o ${dir}/.tmp

        spinny::stop
        NUMOFLINES=$(cat .tmp/brokenLinks_total.txt 2>>"${LOGFILE}" | anew vulns/brokenLinks.txt | sed '/^$/d' | wc -l)
        rftw_util_notification "${NUMOFLINES} new broken links found" info
        end_func "Results are saved in vulns/brokenLinks.txt" ${FUNCNAME[0]}
    else
        if [[ $BROKENLINKS == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function xss() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $XSS == true ]] && [[ -s "gf/xss.txt" ]]; then
        start_func ${FUNCNAME[0]} "XSS Analysis"

        spinny::start

        rftw_vuln_xss -f gf/xss.txt -o ${dir}/vuln

        spinny::stop

        end_func "Results are saved in vulns/xss.txt" ${FUNCNAME[0]}
    else
        if [[ $XSS == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        elif [[ ! -s "gf/xss.txt" ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} No URLs potentially vulnerables to XSS ${reset}\n\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function cors() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $CORS == true ]]; then
        start_func ${FUNCNAME[0]} "CORS Scan"
        [[ ! -s ".tmp/webs_all.txt" ]] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q .tmp/webs_all.txt
        [[ -s ".tmp/webs_all.txt" ]] && python3"${tools}"/Corsy/corsy.py -i .tmp/webs_all.txt -o vulns/cors.txt 2>>"${LOGFILE}" >/dev/null
        end_func "Results are saved in vulns/cors.txt" ${FUNCNAME[0]}
    else
        if [[ $CORS == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function open_redirect() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $OPEN_REDIRECT == true ]] && [[ -s "gf/redirect.txt" ]]; then
        start_func ${FUNCNAME[0]} "Open redirects checks"
        if [[ $DEEP == true ]] || [[ $(cat gf/redirect.txt | wc -l) -le $DEEP_LIMIT ]]; then
            cat gf/redirect.txt | qsreplace FUZZ | sed '/FUZZ/!d' | anew -q .tmp/tmp_redirect.txt
            python3"${tools}"/Oralyzer/oralyzer.py -l .tmp/tmp_redirect.txt -p"${tools}"/Oralyzer/payloads.txt >vulns/redirect.txt
            sed -r -i "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" vulns/redirect.txt
            end_func "Results are saved in vulns/redirect.txt" ${FUNCNAME[0]}
        else
            end_func "Skipping Open redirects: Too many URLs to test, try with --deep flag" ${FUNCNAME[0]}
            printf "${bgreen}#######################################################################${reset}\n"
        fi
    else
        if [[ $OPEN_REDIRECT == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        elif [[ ! -s "gf/redirect.txt" ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} No URLs potentially vulnerables to Open Redirect ${reset}\n\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function ssrf_checks() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SSRF_CHECKS == true ]] && [[ -s "gf/ssrf.txt" ]]; then
        start_func ${FUNCNAME[0]} "SSRF checks"
        spinny::start

        rftw_vuln_ssrf -f gf/ssrf.txt -o ${dir}/vuln

        spinny::stop
    else
        if [[ $SSRF_CHECKS == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        elif [[ ! -s "gf/ssrf.txt" ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} No URLs potentially vulnerables to SSRF ${reset}\n\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function crlf_checks() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $CRLF_CHECKS == true ]]; then
        start_func ${FUNCNAME[0]} "CRLF checks"
        [[ ! -s ".tmp/webs_all.txt" ]] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q .tmp/webs_all.txt
        if [[ $DEEP == true ]] || [[ $(cat .tmp/webs_all.txt | wc -l) -le $DEEP_LIMIT ]]; then
            crlfuzz -l .tmp/webs_all.txt -o vulns/crlf.txt 2>>"${LOGFILE}" >/dev/null
            end_func "Results are saved in vulns/crlf.txt" ${FUNCNAME[0]}
        else
            end_func "Skipping CRLF: Too many URLs to test, try with --deep flag" ${FUNCNAME[0]}
        fi
    else
        if [[ $CRLF_CHECKS == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function lfi() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $LFI == true ]] && [[ -s "gf/lfi.txt" ]]; then
        start_func ${FUNCNAME[0]} "LFI checks"
        if [[ -s "gf/lfi.txt" ]]; then
            cat gf/lfi.txt | qsreplace FUZZ | sed '/FUZZ/!d' | anew -q .tmp/tmp_lfi.txt
            if [[ $DEEP == true ]] || [[ $(cat .tmp/tmp_lfi.txt | wc -l) -le $DEEP_LIMIT ]]; then
                interlace -tL .tmp/tmp_lfi.txt -threads "${INTERLACE_THREADS}" -c "ffuf -v -r -t ${FFUF_THREADS} -rate ${FFUF_RATELIMIT} -H \"${HEADER}\" -w ${lfi_wordlist} -u \"_target_\" -mr \"root:\" " 2>/dev/null | grep "URL" | sed 's/| URL | //' | anew -q vulns/lfi.txt
                end_func "Results are saved in vulns/lfi.txt" ${FUNCNAME[0]}
            else
                end_func "Skipping LFI: Too many URLs to test, try with --deep flag" ${FUNCNAME[0]}
            fi
        fi
    else
        if [[ $LFI == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        elif [[ ! -s "gf/lfi.txt" ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} No URLs potentially vulnerables to LFI ${reset}\n\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function ssti() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SSTI == true ]] && [[ -s "gf/ssti.txt" ]]; then
        start_func ${FUNCNAME[0]} "SSTI checks"
        if [[ -s "gf/ssti.txt" ]]; then
            cat gf/ssti.txt | qsreplace FUZZ | sed '/FUZZ/!d' | anew -q .tmp/tmp_ssti.txt
            if [[ $DEEP == true ]] || [[ $(cat .tmp/tmp_ssti.txt | wc -l) -le $DEEP_LIMIT ]]; then
                interlace -tL .tmp/tmp_ssti.txt -threads "${INTERLACE_THREADS}" -c "ffuf -v -r -t ${FFUF_THREADS} -rate ${FFUF_RATELIMIT} -H \"${HEADER}\" -w ${ssti_wordlist} -u \"_target_\" -mr \"ssti49\" " 2>/dev/null | grep "URL" | sed 's/| URL | //' | anew -q vulns/ssti.txt
                end_func "Results are saved in vulns/ssti.txt" ${FUNCNAME[0]}
            else
                end_func "Skipping SSTI: Too many URLs to test, try with --deep flag" ${FUNCNAME[0]}
            fi
        fi
    else
        if [[ $SSTI == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        elif [[ ! -s "gf/ssti.txt" ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} No URLs potentially vulnerables to SSTI ${reset}\n\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function sqli() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SQLI == true ]] && [[ -s "gf/sqli.txt" ]]; then
        start_func ${FUNCNAME[0]} "SQLi checks"

        cat gf/sqli.txt | qsreplace FUZZ | sed '/FUZZ/!d' | anew -q .tmp/tmp_sqli.txt
        if [[ $DEEP == true ]] || [[ $(cat .tmp/tmp_sqli.txt | wc -l) -le $DEEP_LIMIT ]]; then
            if [[ $SQLMAP == true ]]; then
                python3"${tools}"/sqlmap/sqlmap.py -m .tmp/tmp_sqli.txt -b -o --smart --batch --disable-coloring --random-agent --output-dir=vulns/sqlmap 2>>"${LOGFILE}" >/dev/null
            fi
            if [[ $GHAURI == true ]]; then
                interlace -tL .tmp/tmp_sqli.txt -threads "${INTERLACE_THREADS}" -c "ghauri -u _target_ --batch -H \"${HEADER}\" --force-ssl >> vulns/ghauri_log.txt" 2>>"${LOGFILE}" >/dev/null
            fi
            end_func "Results are saved in vulns/sqlmap folder" ${FUNCNAME[0]}
        else
            end_func "Skipping SQLi: Too many URLs to test, try with --deep flag" ${FUNCNAME[0]}
        fi
    else
        if [[ $SQLI == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        elif [[ ! -s "gf/sqli.txt" ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} No URLs potentially vulnerables to SQLi ${reset}\n\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function test_ssl() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $TEST_SSL == true ]]; then
        start_func ${FUNCNAME[0]} "SSL Test"
        "${tools}"/testssl.sh/testssl.sh --quiet --color 0 -U -iL hosts/ips.txt 2>>"${LOGFILE}" >vulns/testssl.txt
        end_func "Results are saved in vulns/testssl.txt" ${FUNCNAME[0]}
    else
        if [[ $TEST_SSL == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function spraying() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SPRAY == true ]]; then
        start_func ${FUNCNAME[0]} "Password spraying"
        pushd "${tools}/brutespray" &>/dev/null || {
            echo "Failed to cd to brutespray"
            exit 1
        }
        python3 brutespray.py --file "${dir}"/hosts/portscan_active.gnmap --threads $BRUTESPRAY_THREADS --hosts $BRUTESPRAY_CONCURRENCE -o "${dir}"/vulns/brutespray 2>>"${LOGFILE}" >/dev/null
        popd &>/dev/null || {
            echo "Failed to cd back"
            exit 1
        }
        end_func "Results are saved in vulns/brutespray folder" ${FUNCNAME[0]}
    else
        if [[ $SPRAY == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function command_injection() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $COMM_INJ == true ]] && [[ -s "gf/rce.txt" ]]; then
        start_func ${FUNCNAME[0]} "Command Injection checks"
        [[ -s "gf/rce.txt" ]] && cat gf/rce.txt | qsreplace FUZZ | sed '/FUZZ/!d' | anew -q .tmp/tmp_rce.txt
        if [[ $DEEP == true ]] || [[ $(cat .tmp/tmp_rce.txt | wc -l) -le $DEEP_LIMIT ]]; then
            [[ -s ".tmp/tmp_rce.txt" ]] && python3"${tools}"/commix/commix.py --batch -m .tmp/tmp_rce.txt --output-dir vulns/command_injection.txt 2>>"${LOGFILE}" >/dev/null
            end_func "Results are saved in vulns/command_injection folder" ${FUNCNAME[0]}
        else
            end_func "Skipping Command injection: Too many URLs to test, try with --deep flag" ${FUNCNAME[0]}
        fi
    else
        if [[ $COMM_INJ == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        elif [[ ! -s "gf/rce.txt" ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} No URLs potentially vulnerables to Command Injection ${reset}\n\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function 4xxbypass() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $BYPASSER4XX == true ]]; then
        if [[ $(cat fuzzing/fuzzing_full.txt 2>/dev/null | grep -E '^4' | grep -Ev '^404' | cut -d ' ' -f3 | wc -l) -le 1000 ]] || [[ $DEEP == true ]]; then
            start_func "403 bypass"
            cat "${dir}"/fuzzing/fuzzing_full.txt 2>/dev/null | grep -E '^4' | grep -Ev '^404' | cut -d ' ' -f3 >"${dir}"/.tmp/403test.txt
            pushd "${tools}/dontgo403" &>/dev/null || {
                echo "Failed to cd to dontgo403"
                exit 1
            }
            interlace -tL ${dir}/.tmp/403test.txt -threads "${INTERLACE_THREADS}" -c "./dontgo403 -a ${HEADER} _target_ -a \"${HEADER}\" >> "${dir}"/.tmp/dontgo403.txt" 2>>"${LOGFILE}" >/dev/null
            popd &>/dev/null || {
                echo "Failed to cd back"
                exit 1
            }
            [[ -s ".tmp/dontgo403.txt" ]] && cat .tmp/dontgo403.txt | anew -q vulns/dontgo403.txt
            end_func "Results are saved in vulns/dontgo403.txt" ${FUNCNAME[0]}
        else
            rftw_util_notification "Too many urls to bypass, skipping" warn
        fi
    else
        if [[ $BYPASSER4XX == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function prototype_pollution() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $PROTO_POLLUTION == true ]]; then
        start_func ${FUNCNAME[0]} "Prototype Pollution checks"
        if [[ $DEEP == true ]] || [[ $(cat webs/url_extract.txt | wc -l) -le $DEEP_LIMIT ]]; then
            [[ -s "webs/url_extract.txt" ]] && ppfuzz -l webs/url_extract.txt -c $PPFUZZ_THREADS 2>/dev/null | anew -q .tmp/prototype_pollution.txt
            [[ -s ".tmp/prototype_pollution.txt" ]] && cat .tmp/prototype_pollution.txt | sed -e '1,8d' | sed '/^\[ERR/d' | anew -q vulns/prototype_pollution.txt
            end_func "Results are saved in vulns/prototype_pollution.txt" ${FUNCNAME[0]}
        else
            end_func "Skipping Prototype Pollution: Too many URLs to test, try with --deep flag" ${FUNCNAME[0]}
        fi
    else
        if [[ $PROTO_POLLUTION == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function smuggling() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SMUGGLING == true ]]; then
        start_func ${FUNCNAME[0]} "HTTP Request Smuggling checks"
        [[ ! -s ".tmp/webs_all.txt" ]] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q .tmp/webs_all.txt
        if [[ $DEEP == true ]] || [[ $(cat .tmp/webs_all.txt | wc -l) -le $DEEP_LIMIT ]]; then
            pushd "${tools}/smuggler" &>/dev/null || {
                echo "Failed to cd to smuggler"
                exit 1
            }
            cat "${dir}"/.tmp/webs_all.txt | python3 smuggler.py -q --no-color 2>/dev/null | anew -q "${dir}"/.tmp/smuggling.txt
            pophd &>/dev/null || {
                echo "Failed to cd back"
                exit 1
            }
            [[ -s ".tmp/smuggling.txt" ]] && cat .tmp/smuggling.txt | anew -q vulns/smuggling.txt
            end_func "Results are saved in vulns/smuggling.txt" ${FUNCNAME[0]}
        else
            end_func "Skipping Prototype Pollution: Too many webs to test, try with --deep flag" ${FUNCNAME[0]}
        fi
    else
        if [[ $SMUGGLING == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function webcache() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $WEBCACHE == true ]]; then
        start_func ${FUNCNAME[0]} "Web Cache Poisoning checks"
        [[ ! -s ".tmp/webs_all.txt" ]] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q .tmp/webs_all.txt
        if [[ $DEEP == true ]] || [[ $(cat .tmp/webs_all.txt | wc -l) -le $DEEP_LIMIT ]]; then
            pushd "${tools}/Web-Cache-Vulnerability-Scanner" &>/dev/null || {
                echo "Failed to cd to Web-Cache-Vulnerability-Scanner"
                exit 1
            }
            Web-Cache-Vulnerability-Scanner -u file:"${dir}"/.tmp/webs_all.txt -v 0 2>/dev/null | anew -q "${dir}"/.tmp/webcache.txt
            popd &>/dev/null || {
                echo "Failed to cd back"
                exit 1
            }
            [[ -s ".tmp/webcache.txt" ]] && cat .tmp/webcache.txt | anew -q vulns/webcache.txt
            end_func "Results are saved in vulns/webcache.txt" ${FUNCNAME[0]}
        else
            end_func "Web Cache Poisoning: Too many webs to test, try with --deep flag" ${FUNCNAME[0]}
        fi
    else
        if [[ $WEBCACHE == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

function fuzzparams() {
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $FUZZPARAMS == true ]]; then
        start_func ${FUNCNAME[0]} "Fuzzing params values checks"
        if [[ $DEEP == true ]] || [[ $(cat webs/url_extract.txt | wc -l) -le $DEEP_LIMIT2 ]]; then
            if [[ ! ${AXIOM} == true ]]; then
                nuclei -update 2>>"${LOGFILE}" >/dev/null
                git -C"${tools}"/fuzzing-templates pull
                cat webs/url_extract.txt 2>/dev/null | nuclei -silent -retries 3 -rl $NUCLEI_RATELIMIT -t"${tools}"/fuzzing-templates -o .tmp/fuzzparams.txt
            else
                axiom-exec "git clone https://github.com/projectdiscovery/fuzzing-templates /home/op/fuzzing-templates" &>/dev/null
                axiom-scan webs/url_extract.txt -m nuclei -nh -retries 3 -w /home/op/fuzzing-templates -rl $NUCLEI_RATELIMIT -o .tmp/fuzzparams.txt "${AXIOM_EXTRA_ARGS}" 2>>"${LOGFILE}" >/dev/null
            fi
            [[ -s ".tmp/fuzzparams.txt" ]] && cat .tmp/fuzzparams.txt | anew -q vulns/fuzzparams.txt
            end_func "Results are saved in vulns/fuzzparams.txt" ${FUNCNAME[0]}
        else
            end_func "Fuzzing params values: Too many entries to test, try with --deep flag" ${FUNCNAME[0]}
        fi
    else
        if [[ $FUZZPARAMS == false ]]; then
            printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi
}

###############################################################################################################
########################################## OPTIONS & MGMT #####################################################
###############################################################################################################

function rftw_util_deleteoos() {
    if [[ -s $1 ]]; then
        cat $1 | while read outscoped; do
            if grep -q "^[*]" <<<$outscoped; then
                outscoped="${outscoped:1}"
                sed -i /"$outscoped$"/d $2
            else
                sed -i /$outscoped/d $2
            fi
        done
    fi
}

function getElapsedTime {
    runtime=""
    local T=$2-$1
    local D=$((T / 60 / 60 / 24))
    local H=$((T / 60 / 60 % 24))
    local M=$((T / 60 % 60))
    local S=$((T % 60))
    ((D > 0)) && runtime="${runtime}$D days, "
    ((H > 0)) && runtime="${runtime}$H hours, "
    ((M > 0)) && runtime="${runtime}$M minutes, "
    runtime="${runtime}$S seconds."
}

function zipSnedOutputFolder {
    zip_name1=$(date +"%Y_%m_%d-%H.%M.%S")
    zip_name="${zip_name1}_${DOMAIN}.zip" 2>>"${LOGFILE}" >/dev/null
    (cd "${dir}" && zip -r "$zip_name" .)

    echo "Sending zip file "${dir}/${zip_name}""
    if [[ -s "${dir}/$zip_name" ]]; then
        rftw_util_sendnotify ${dir}/$zip_name
        rm -f "${dir}/$zip_name"
    else
        rftw_util_notification "No Zip file to send" warn
    fi
}

function isAsciiText {
    IS_ASCII="False"
    if [[ $(file $1 | grep -o 'ASCII text$') == "ASCII text" ]]; then
        IS_ASCII="True"
    else
        IS_ASCII="False"
    fi
}

function output() {
    mkdir -p $dir_output
    cp -r $dir $dir_output
    [[ "$(dirname $dir)" != "$dir_output" ]] && rm -rf "${dir}"
}

function remove_big_files() {
    eval rm -rf .tmp/gotator*.txt 2>>"${LOGFILE}"
    eval rm -rf .tmp/brute_recursive_wordlist.txt 2>>"${LOGFILE}"
    eval rm -rf .tmp/subs_dns_tko.txt 2>>"${LOGFILE}"
    eval rm -rf .tmp/subs_no_resolved.txt .tmp/subdomains_dns.txt .tmp/brute_dns_tko.txt .tmp/scrap_subs.txt .tmp/analytics_subs_clean.txt .tmp/gotator1.txt .tmp/gotator2.txt .tmp/passive_recursive.txt .tmp/brute_recursive_wordlist.txt .tmp/gotator1_recursive.txt .tmp/gotator2_recursive.txt 2>>"${LOGFILE}"
    eval find .tmp -type f -size +200M -exec rm -f {} + 2>>"${LOGFILE}"
}

function transfer {
    if [[ $# -eq 0 ]]; then
        echo "No arguments specified.\nUsage:\n transfer <file|directory>\n ... | transfer <file_name>" >&2
        return 1
    fi
    if tty -s; then
        file="$1"
        file_name=$(basename "$file")
        if [[ ! -e $file ]]; then
            echo "$file: No such file or directory" >&2
            return 1
        fi
        if [[ -d $file ]]; then
            file_name="$file_name.zip"
            (cd "$file" && zip -r -q - .) | curl --progress-bar --upload-file "-" "https://transfer.sh/$file_name" | tee /dev/null
        else
            cat "$file" | curl --progress-bar --upload-file "-" "https://transfer.sh/$file_name" | tee /dev/null
        fi
    else
        file_name=$1
        curl --progress-bar --upload-file "-" "https://transfer.sh/$file_name" | tee /dev/null
    fi
}

function start_func() {
    printf "${bgreen}#######################################################################"
    rftw_util_notification "${2}" info
    echo "[ $(date +"%F %T") ]] Start function : ${1} " >>"${LOGFILE}"
    start=$(date +%s)
}

function end_func() {
    touch $called_fn_dir/.${2}
    end=$(date +%s)
    getElapsedTime $start $end
    rftw_util_notification "${2} Finished in ${runtime}" info
    echo "[ $(date +"%F %T") ]] End function : ${2} " >>"${LOGFILE}"
    printf "${bblue} ${1} ${reset}\n"
    printf "${bgreen}#######################################################################${reset}\n"
}

function start_subfunc() {
    rftw_util_notification "${2}" warn
    echo "[ $(date +"%F %T") ]] Start subfunction : ${1} " >>"${LOGFILE}"
    start_sub=$(date +%s)
}

function end_subfunc() {
    touch $called_fn_dir/.${2}
    end_sub=$(date +%s)
    getElapsedTime $start_sub $end_sub
    rftw_util_notification "${1} in ${runtime}" good
    echo "[ $(date +"%F %T") ]] End subfunction : ${1} " >>"${LOGFILE}"
}

function check_inscope() {
    cat $1 | inscope >$1_tmp && cp $1_tmp $1 && rm -f $1_tmp
}

function ipcidr_target() {
    IP_CIDR_REGEX='(((25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?))(\/([8-9]|[1-2][0-9]|3[0-2]))([^0-9.]|$)|(((25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)$)'
    if [[ $1 =~ ^${IP_CIDR_REGEX} ]]; then
        echo $1 | mapcidr -silent | anew -q target_reconftw_ipcidr.txt
        if [[ -s "./target_reconftw_ipcidr.txt" ]]; then
            [[ $REVERSE_IP == true ]] && cat ./target_reconftw_ipcidr.txt | hakip2host | cut -d' ' -f 3 | unfurl -u domains 2>/dev/null | sed -e 's/*\.//' -e 's/\.$//' -e '/\./!d' | anew -q ./target_reconftw_ipcidr.txt
            if [[ $(cat ./target_reconftw_ipcidr.txt | wc -l) -eq 1 ]]; then
                DOMAIN=$(cat ./target_reconftw_ipcidr.txt)
            elif [[ $(cat ./target_reconftw_ipcidr.txt | wc -l) -gt 1 ]]; then
                unset domain
                list=${PWD}/target_reconftw_ipcidr.txt
            fi
        fi
        if [[ -n $2 ]]; then
            cat $list | anew -q $2
            sed -i '/\/[0-9]*$/d' $2
        fi
    fi
}

function start() {

    global_start=$(date +%s)

    if [[ $NOTIFICATION == true ]]; then
        NOTIFY="notify -silent"
    else
        NOTIFY=""
    fi

    printf "\n${bgreen}#######################################################################${reset}"
    rftw_util_notification "Recon succesfully started on ${DOMAIN}" good
    [[ $SOFT_NOTIFICATION == true ]] && echo "Recon succesfully started on ${DOMAIN}" | notify -silent
    printf "${bgreen}#######################################################################${reset}\n"
    if [[ $upgrade_before_running == true ]]; then
        ${SCRIPTPATH}/install.sh --tools
    fi
    rftw_util_tools

    if [[ -z ${DOMAIN} ]]; then
        if [[ -n $list ]]; then
            if [[ -z ${DOMAIN} ]]; then
                DOMAIN="Multi"
                dir="$SCRIPTPATH/Recon/$DOMAIN"
                called_fn_dir="${dir}"/.called_fn
            fi
            if [[ $list == /* ]]; then
                install -D "$list" "${dir}"/webs/webs.txt
            else
                install -D "$SCRIPTPATH"/"$list" "${dir}"/webs/webs.txt
            fi
        fi
    else
        dir="$SCRIPTPATH/Recon/$DOMAIN"
        called_fn_dir="${dir}"/.called_fn
    fi

    if [[ -z ${DOMAIN} ]]; then
        rftw_util_notification "\n\n${bred} No domain or list provided ${reset}\n\n" error
        exit
    fi

    if [[ ! -d $called_fn_dir ]]; then
        mkdir -p "$called_fn_dir"
    fi
    mkdir -p "${dir}"
    cd "${dir}" || {
        echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"
        exit 1
    }
    if [[ ${AXIOM} == true ]]; then
        if [[ -n ${DOMAIN} ]]; then
            echo "${DOMAIN}" | anew -q target.txt
            list="${dir}/target.txt"
        fi
    fi
    mkdir -p .tmp .log osint subdomains webs hosts vulns

    NOW=$(date +"%F")
    NOWT=$(date +"%T")
    LOGFILE="${dir}/.log/${NOW}_${NOWT}.txt"
    touch .log/${NOW}_${NOWT}.txt
    echo "Start ${NOW} ${NOWT}" >"${LOGFILE}"

    printf "\n"
    printf "${bred} Target: ${DOMAIN}\n\n"

}

function end() {

    find $dir -type f -empty -print | grep -v '.called_fn' | grep -v '.log' | grep -v '.tmp' | xargs rm -f 2>>"${LOGFILE}" >/dev/null
    find $dir -type d -empty -print -delete 2>>"${LOGFILE}" >/dev/null

    echo "End $(date +"%F") $(date +"%T")" >>"${LOGFILE}"

    if [[ ! $PRESERVE == true ]]; then
        find $dir -type f -empty | grep -v "called_fn" | xargs rm -f 2>>"${LOGFILE}" >/dev/null
        find $dir -type d -empty | grep -v "called_fn" | xargs rm -rf 2>>"${LOGFILE}" >/dev/null
    fi

    if [[ $REMOVETMP == true ]]; then
        rm -rf "${dir}"/.tmp
    fi

    if [[ $REMOVELOG == true ]]; then
        rm -rf "${dir}"/.log
    fi

    if [[ -n $dir_output ]]; then
        output
        finaldir=$dir_output
    else
        finaldir=$dir
    fi
    #Zip the output folder and send it via tg/discord/slack
    if [[ $SENDZIPNOTIFY == true ]]; then
        zipSnedOutputFolder
    fi
    global_end=$(date +%s)
    getElapsedTime $global_start $global_end
    printf "${bgreen}#######################################################################${reset}\n"
    rftw_util_notification "Finished Recon on: ${DOMAIN} under ${finaldir} in: ${runtime}" good
    [[ $SOFT_NOTIFICATION == true ]] && echo "Finished Recon on: ${DOMAIN} under ${finaldir} in: ${runtime}" | notify -silent
    printf "${bgreen}#######################################################################${reset}\n"
    #Seperator for more clear messges in telegram_Bot
    echo "******  Stay safe 🦠 and secure 🔐  ******" | ${NOTIFY}
}

###############################################################################################################
########################################### MODES & MENUS #####################################################
###############################################################################################################

function passive() {
    start
    domain_info
    ip_info
    emails
    google_dorks
    github_dorks
    github_repos
    metadata
    postleaks
    SUBNOERROR=false
    SUBANALYTICS=false
    SUBBRUTE=false
    SUBSCRAPING=false
    SUBPERMUTE=false
    SUBREGEXPERMUTE=false
    SUB_RECURSIVE_BRUTE=false
    WEBPROBESIMPLE=false
    if [[ ${AXIOM} == true ]]; then
        rftw_util_axiomon
        rftw_util_axiomsel
    fi

    subdomains_full
    remove_big_files
    favicon
    cdnprovider
    PORTSCAN_ACTIVE=false
    portscan

    if [[ ${AXIOM} == true ]]; then
        rftw_util_axiomoff
    fi

    end
}

function all() {
    start
    recon
    vulns
    end
}

function osint() {
    domain_info
    ip_info
    emails
    google_dorks
    github_dorks
    github_repos
    metadata
    postleaks
    zonetransfer
    favicon
}

function vulns() {
    if [[ $VULNS_GENERAL == true ]]; then
        cors
        open_redirect
        ssrf_checks
        crlf_checks
        lfi
        ssti
        sqli
        xss
        command_injection
        prototype_pollution
        smuggling
        webcache
        spraying
        brokenLinks
        fuzzparams
        4xxbypass
        test_ssl
    fi
}

function multi_osint() {

    global_start=$(date +%s)

    if [[ $NOTIFICATION == true ]]; then
        NOTIFY="notify -silent"
    else
        NOTIFY=""
    fi

    #[[ -n "${DOMAIN}" ]] && ipcidr_target${DOMAIN}/

    if [[ -s $list ]]; then
        sed -i 's/\r$//' $list
        targets=$(cat $list)
    else
        rftw_util_notification "Target list not provided" error
        exit
    fi

    workdir=$SCRIPTPATH/Recon/$multi
    mkdir -p $workdir || {
        echo "Failed to create directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"
        exit 1
    }
    cd "$workdir" || {
        echo "Failed to cd directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"
        exit 1
    }
    mkdir -p .tmp .called_fn osint subdomains webs hosts vulns

    NOW=$(date +"%F")
    NOWT=$(date +"%T")
    LOGFILE="${workdir}/.log/${NOW}_${NOWT}.txt"
    touch .log/${NOW}_${NOWT}.txt
    echo "Start ${NOW} ${NOWT}" >"${LOGFILE}"

    for domain in $targets; do
        dir=$workdir/targets/$DOMAIN
        called_fn_dir="${dir}"/.called_fn
        mkdir -p $dir
        cd "${dir}" || {
            echo "Failed to cd directory '$dir' in ${FUNCNAME[0]} @ line ${LINENO}"
            exit 1
        }
        mkdir -p .tmp .called_fn osint subdomains webs hosts vulns
        NOW=$(date +"%F")
        NOWT=$(date +"%T")
        LOGFILE="${dir}/.log/${NOW}_${NOWT}.txt"
        touch .log/${NOW}_${NOWT}.txt
        echo "Start ${NOW} ${NOWT}" >"${LOGFILE}"
        domain_info
        ip_info
        emails
        google_dorks
        github_dorks
        github_repos
        metadata
        postleaks
        zonetransfer
        favicon
    done
    cd "$workdir" || {
        echo "Failed to cd directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"
        exit 1
    }
    dir=$workdir
    DOMAIN=$multi
    end
}

function recon() {
    domain_info
    ip_info
    emails
    google_dorks
    github_dorks
    github_repos
    metadata
    postleaks
    zonetransfer
    favicon

    if [[ ${AXIOM} == true ]]; then
        rftw_util_axiomon
        rftw_util_axiomsel
    fi

    subdomains_full
    webprobe_full
    subtakeover
    remove_big_files
    s3buckets
    screenshot
    #	virtualhosts
    cdnprovider
    portscan
    waf_checks
    nuclei_check
    fuzz
    urlchecks
    jschecks

    if [[ ${AXIOM} == true ]]; then
        rftw_util_axiomoff
    fi

    cms_scanner
    url_gf
    wordlist_gen
    wordlist_gen_roboxtractor
    password_dict
    url_ext
}

function multi_recon() {

    global_start=$(date +%s)

    if [[ $NOTIFICATION == true ]]; then
        NOTIFY="notify -silent"
    else
        NOTIFY=""
    fi

    #[[ -n "${DOMAIN}" ]] && ipcidr_target${DOMAIN}/

    if [[ -s $list ]]; then
        sed -i 's/\r$//' $list
        targets=$(cat $list)
    else
        rftw_util_notification "Target list not provided" error
        exit
    fi

    workdir=$SCRIPTPATH/Recon/$multi
    mkdir -p $workdir || {
        echo "Failed to create directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"
        exit 1
    }
    cd "$workdir" || {
        echo "Failed to cd directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"
        exit 1
    }

    mkdir -p .tmp .log .called_fn osint subdomains webs hosts vulns
    NOW=$(date +"%F")
    NOWT=$(date +"%T")
    LOGFILE="${workdir}/.log/${NOW}_${NOWT}.txt"
    touch .log/${NOW}_${NOWT}.txt
    echo "Start ${NOW} ${NOWT}" >"${LOGFILE}"

    [[ -n $flist ]] && LISTTOTAL=$(cat "$flist" | wc -l)

    for domain in $targets; do
        dir=$workdir/targets/$DOMAIN
        called_fn_dir="${dir}"/.called_fn
        mkdir -p $dir
        cd "${dir}" || {
            echo "Failed to cd directory '$dir' in ${FUNCNAME[0]} @ line ${LINENO}"
            exit 1
        }
        mkdir -p .tmp .log .called_fn osint subdomains webs hosts vulns

        NOW=$(date +"%F")
        NOWT=$(date +"%T")
        LOGFILE="${dir}/.log/${NOW}_${NOWT}.txt"
        touch .log/${NOW}_${NOWT}.txt
        echo "Start ${NOW} ${NOWT}" >"${LOGFILE}"
        loopstart=$(date +%s)

        domain_info
        ip_info
        emails
        google_dorks
        github_dorks
        github_repos
        metadata
        postleaks
        zonetransfer
        favicon
        currently=$(date +"%H:%M:%S")
        loopend=$(date +%s)
        getElapsedTime $loopstart $loopend
        printf "${bgreen}#######################################################################${reset}\n"
        printf "${bgreen} "${DOMAIN}" finished 1st loop in ${runtime}  $currently ${reset}\n"
        if [[ -n $flist ]]; then
            POSINLIST=$(eval grep -nrE "^$DOMAIN$" "$flist" | cut -f1 -d':')
            printf "\n${yellow}  "${DOMAIN}" is $POSINLIST of $LISTTOTAL${reset}\n"
        fi
        printf "${bgreen}#######################################################################${reset}\n"
    done
    cd "$workdir" || {
        echo "Failed to cd directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"
        exit 1
    }

    if [[ ${AXIOM} == true ]]; then
        rftw_util_axiomon
        rftw_util_axiomsel
    fi

    for domain in $targets; do
        loopstart=$(date +%s)
        dir=$workdir/targets/$DOMAIN
        called_fn_dir="${dir}"/.called_fn
        cd "${dir}" || {
            echo "Failed to cd directory '$dir' in ${FUNCNAME[0]} @ line ${LINENO}"
            exit 1
        }
        subdomains_full
        webprobe_full
        subtakeover
        remove_big_files
        screenshot
        #		virtualhosts
        cdnprovider
        portscan
        currently=$(date +"%H:%M:%S")
        loopend=$(date +%s)
        getElapsedTime $loopstart $loopend
        printf "${bgreen}#######################################################################${reset}\n"
        printf "${bgreen} "${DOMAIN}" finished 2nd loop in ${runtime}  $currently ${reset}\n"
        if [[ -n $flist ]]; then
            POSINLIST=$(eval grep -nrE "^$DOMAIN$" "$flist" | cut -f1 -d':')
            printf "\n${yellow}  "${DOMAIN}" is $POSINLIST of $LISTTOTAL${reset}\n"
        fi
        printf "${bgreen}#######################################################################${reset}\n"
    done
    cd "$workdir" || {
        echo "Failed to cd directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"
        exit 1
    }

    rftw_util_notification "############################# Total data ############################" info
    NUMOFLINES_users_total=$(find . -type f -name 'users.txt' -exec cat {} + | anew osint/users.txt | sed '/^$/d' | wc -l)
    NUMOFLINES_pwndb_total=$(find . -type f -name 'passwords.txt' -exec cat {} + | anew osint/passwords.txt | sed '/^$/d' | wc -l)
    NUMOFLINES_software_total=$(find . -type f -name 'software.txt' -exec cat {} + | anew osint/software.txt | sed '/^$/d' | wc -l)
    NUMOFLINES_authors_total=$(find . -type f -name 'authors.txt' -exec cat {} + | anew osint/authors.txt | sed '/^$/d' | wc -l)
    NUMOFLINES_subs_total=$(find . -type f -name 'subdomains.txt' -exec cat {} + | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l)
    NUMOFLINES_subtko_total=$(find . -type f -name 'takeover.txt' -exec cat {} + | anew webs/takeover.txt | sed '/^$/d' | wc -l)
    NUMOFLINES_webs_total=$(find . -type f -name 'webs.txt' -exec cat {} + | anew webs/webs.txt | sed '/^$/d' | wc -l)
    NUMOFLINES_webs_total=$(find . -type f -name 'webs_uncommon_ports.txt' -exec cat {} + | anew webs/webs_uncommon_ports.txt | sed '/^$/d' | wc -l)
    NUMOFLINES_ips_total=$(find . -type f -name 'ips.txt' -exec cat {} + | anew hosts/ips.txt | sed '/^$/d' | wc -l)
    NUMOFLINES_cloudsprov_total=$(find . -type f -name 'cdn_providers.txt' -exec cat {} + | anew hosts/cdn_providers.txt | sed '/^$/d' | wc -l)
    find . -type f -name 'portscan_active.txt' -exec cat {} + | tee -a hosts/portscan_active.txt >>"${LOGFILE}" 2>&1 >/dev/null
    find . -type f -name 'portscan_active.gnmap' -exec cat {} + | tee hosts/portscan_active.gnmap 2>>"${LOGFILE}" >/dev/null
    find . -type f -name 'portscan_passive.txt' -exec cat {} + | tee hosts/portscan_passive.txt 2>&1 >>"${LOGFILE}" >/dev/null

    rftw_util_notification "- ${NUMOFLINES_users_total} total users found" good
    rftw_util_notification "- ${NUMOFLINES_pwndb_total} total creds leaked" good
    rftw_util_notification "- ${NUMOFLINES_software_total} total software found" good
    rftw_util_notification "- ${NUMOFLINES_authors_total} total authors found" good
    rftw_util_notification "- ${NUMOFLINES_subs_total} total subdomains" good
    rftw_util_notification "- ${NUMOFLINES_subtko_total} total probably subdomain takeovers" good
    rftw_util_notification "- ${NUMOFLINES_webs_total} total websites" good
    rftw_util_notification "- ${NUMOFLINES_ips_total} total ips" good
    rftw_util_notification "- ${NUMOFLINES_cloudsprov_total} total IPs belongs to cloud" good
    s3buckets
    waf_checks
    nuclei_check
    for domain in $targets; do
        loopstart=$(date +%s)
        dir=$workdir/targets/$DOMAIN
        called_fn_dir="${dir}"/.called_fn
        cd "${dir}" || {
            echo "Failed to cd directory '$dir' in ${FUNCNAME[0]} @ line ${LINENO}"
            exit 1
        }
        loopstart=$(date +%s)
        fuzz
        urlchecks
        jschecks
        currently=$(date +"%H:%M:%S")
        loopend=$(date +%s)
        getElapsedTime $loopstart $loopend
        printf "${bgreen}#######################################################################${reset}\n"
        printf "${bgreen} "${DOMAIN}" finished 3rd loop in ${runtime}  $currently ${reset}\n"
        if [[ -n $flist ]]; then
            POSINLIST=$(eval grep -nrE "^$DOMAIN$" "$flist" | cut -f1 -d':')
            printf "\n${yellow}  "${DOMAIN}" is $POSINLIST of $LISTTOTAL${reset}\n"
        fi
        printf "${bgreen}#######################################################################${reset}\n"
    done

    if [[ ${AXIOM} == true ]]; then
        rftw_util_axiomoff
    fi

    for domain in $targets; do
        loopstart=$(date +%s)
        dir=$workdir/targets/$DOMAIN
        called_fn_dir="${dir}"/.called_fn
        cd "${dir}" || {
            echo "Failed to cd directory '$dir' in ${FUNCNAME[0]} @ line ${LINENO}"
            exit 1
        }
        cms_scanner
        url_gf
        wordlist_gen
        wordlist_gen_roboxtractor
        password_dict
        url_ext
        currently=$(date +"%H:%M:%S")
        loopend=$(date +%s)
        getElapsedTime $loopstart $loopend
        printf "${bgreen}#######################################################################${reset}\n"
        printf "${bgreen} "${DOMAIN}" finished final loop in ${runtime}  $currently ${reset}\n"
        if [[ -n $flist ]]; then
            POSINLIST=$(eval grep -nrE "^$DOMAIN$" "$flist" | cut -f1 -d':')
            printf "\n${yellow}  "${DOMAIN}" is $POSINLIST of $LISTTOTAL${reset}\n"
        fi
        printf "${bgreen}#######################################################################${reset}\n"
    done
    cd "$workdir" || {
        echo "Failed to cd directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"
        exit 1
    }
    dir=$workdir
    DOMAIN=$multi
    end
}

function subs_menu() {
    start

    if [[ ${AXIOM} == true ]]; then
        rftw_util_axiomon
        rftw_util_axiomsel
    fi

    subdomains_full
    webprobe_full
    subtakeover
    remove_big_files
    screenshot
    #	virtualhosts
    zonetransfer
    s3buckets

    if [[ ${AXIOM} == true ]]; then
        rftw_util_axiomoff
    fi

    end
}

function webs_menu() {
    subtakeover
    remove_big_files
    screenshot
    #	virtualhosts
    waf_checks
    nuclei_check
    cms_scanner
    fuzz
    urlchecks
    jschecks
    url_gf
    wordlist_gen
    wordlist_gen_roboxtractor
    password_dict
    url_ext
    vulns
    end
}

function help() {
    printf "\n $(basename "$0") [-d domain.tld] [-m name] [-l list.txt] [-x oos.txt] [-i in.txt] "
    printf "\n           	      [-r] [-s] [-p] [-a] [-w] [-n] [-i] [-h] [-f] [--deep] [-o OUTPUT]\n\n"
    printf " ${bblue}TARGET OPTIONS${reset}\n"
    printf "   -d domain.tld     Target domain\n"
    printf "   -m company        Target company name\n"
    printf "   -l list.txt       Targets list (One on each line)\n"
    printf "   -x oos.txt        Exclude subdomains list (Out Of Scope)\n"
    printf "   -i in.txt         Include subdomains list\n"
    printf " \n"
    printf " ${bblue}MODE OPTIONS${reset}\n"
    printf "   -r, --recon       Recon - Perform full recon process (without attacks)\n"
    printf "   -s, --subdomains  Subdomains - Perform Subdomain Enumeration, Web probing and check for sub-tko\n"
    printf "   -p, --passive     Passive - Perform only passive steps\n"
    printf "   -a, --all         All - Perform all checks and active exploitations\n"
    printf "   -w, --web         Web - Perform web checks from list of subdomains\n"
    printf "   -n, --osint       OSINT - Check for public intel data\n"
    printf "   -c, --custom      Custom - Launches specific function against target, u need to know the function name first\n"
    printf "   -h                Help - Show help section\n"
    printf " \n"
    printf " ${bblue}GENERAL OPTIONS${reset}\n"
    printf "   --deep            Deep scan (Enable some slow options for deeper scan)\n"
    printf "   -f config_file    Alternate reconftw.cfg file\n"
    printf "   -o output/path    Define output folder\n"
    printf "   -v, --vps         Axiom distributed VPS \n"
    printf "   -q                Rate limit in requests per second \n"
    printf " \n"
    printf " ${bblue}USAGE EXAMPLES${reset}\n"
    printf " ${byellow}Perform full recon (without attacks):${reset}\n"
    printf " ./reconftw.sh -d example.com -r\n"
    printf " \n"
    printf " ${byellow}Perform subdomain enumeration on multiple targets:${reset}\n"
    printf " ./reconftw.sh -l targets.txt -s\n"
    printf " \n"
    printf " ${byellow}Perform Web based scanning on a subdomains list:${reset}\n"
    printf " ./reconftw.sh -d example.com -l targets.txt -w\n"
    printf " \n"
    printf " ${byellow}Multidomain recon:${reset}\n"
    printf " ./reconftw.sh -m company -l domainlist.txt -r\n"
    printf " \n"
    printf " ${byellow}Perform full recon (with active attacks) along Out-Of-Scope subdomains list:${reset}\n"
    printf " ./reconftw.sh -d example.com -x out.txt -a\n"
    printf " \n"
    printf " ${byellow}Perform full recon and store output to specified directory:${reset}\n"
    printf " ./reconftw.sh -d example.com -r -o custom/path\n"
    printf " \n"
    printf " ${byellow}Run custom function:${reset}\n"
    printf " ./reconftw.sh -d example.com -c nuclei_check \n"
}

###############################################################################################################
########################################### START SCRIPT  #####################################################
###############################################################################################################

source $HOME/.reconftw/assets/spinny/spinny.sh

# macOS PATH initialization, thanks @0xtavian <3
if [[ $OSTYPE == "darwin"* ]]; then
    PATH="/usr/local/opt/gnu-getopt/bin:$PATH"
    PATH="/usr/local/opt/coreutils/libexec/gnubin:$PATH"
fi

PROGARGS=$(getopt -o 'd:m:l:x:i:o:f:q:c:rspanwvh::' --long 'domain:,list:,recon,subdomains,passive,all,web,osint,deep,help,vps' -n 'reconFTW' -- "$@")

# Note the quotes around "$PROGARGS": they are essential!
eval set -- "$PROGARGS"
unset PROGARGS

while true; do
    case "$1" in
    '-d' | '--domain')
        DOMAIN=$2
        ipcidr_target $2
        shift 2
        continue
        ;;
    '-m')
        multi=$2
        shift 2
        continue
        ;;
    '-l' | '--list')
        list=$2
        for t in $(cat $list); do
            ipcidr_target $t $list
        done
        shift 2
        continue
        ;;
    '-x')
        outOfScope_file=$2
        shift 2
        continue
        ;;
    '-i')
        inScope_file=$2
        shift 2
        continue
        ;;
    # modes
    '-r' | '--recon')
        opt_mode='r'
        shift
        continue
        ;;
    '-s' | '--subdomains')
        opt_mode='s'
        shift
        continue
        ;;
    '-p' | '--passive')
        opt_mode='p'
        shift
        continue
        ;;
    '-a' | '--all')
        opt_mode='a'
        shift
        continue
        ;;
    '-w' | '--web')
        opt_mode='w'
        shift
        continue
        ;;
    '-n' | '--osint')
        opt_mode='n'
        shift
        continue
        ;;
    '-c' | '--custom')
        custom_function=$2
        opt_mode='c'
        shift 2
        continue
        ;;
    # extra stuff
    '-o')
        if [[ $2 != /* ]]; then
            dir_output=$PWD/$2
        else
            dir_output=$2
        fi
        shift 2
        continue
        ;;
    '-v' | '--vps')
        which axiom-ls &>/dev/null || {
            printf "\n Axiom is needed for this mode and is not installed \n You have to install it manually \n" && exit
        }
        AXIOM=true
        shift
        continue
        ;;
    '-f')
        CUSTOM_CONFIG=$2
        shift 2
        continue
        ;;
    '-q')
        rate_limit=$2
        shift 2
        continue
        ;;
    '--deep')
        opt_deep=true
        shift
        continue
        ;;

    '--')
        shift
        break
        ;;
    '--help' | '-h' | *)
        # echo "Unknown argument: $1"
        . ./reconftw.cfg
        banner
        help
        rftw_util_tools -t "${tools}"
        exit 1
        ;;
    esac
done

# This is the first thing to do to read in alternate config
SCRIPTPATH="$(
    cd "$(dirname "$0")" >/dev/null 2>&1 || exit
    pwd -P
)"
. "$SCRIPTPATH"/reconftw.cfg || {
    echo "Error importing reconftw.ctg"
    exit 1
}
if [[ -s $CUSTOM_CONFIG ]]; then
    # shellcheck source=/home/six2dez/Tools/reconftw/custom_config.cfg
    . "${CUSTOM_CONFIG}" || {
        echo "Error importing reconftw.ctg"
        exit 1
    }
fi

if [[ $opt_deep ]]; then
    DEEP=true
fi

if [[ $rate_limit ]]; then
    NUCLEI_RATELIMIT=$rate_limit
    FFUF_RATELIMIT=$rate_limit
    HTTPX_RATELIMIT=$rate_limit
fi

if [[ -n $outOfScope_file ]]; then
    isAsciiText $outOfScope_file
    if [[ "False" == "$IS_ASCII" ]]; then
        printf "\n\n${bred} Out of Scope file is not a text file${reset}\n\n"
        exit
    fi
fi

if [[ -n "${INSCOPE_file}" ]]; then
    isAsciiText ${INSCOPE_file}
    if [[ "False" == "$IS_ASCII" ]]; then
        printf "\n\n${bred} In Scope file is not a text file${reset}\n\n"
        exit
    fi
fi

if [[ $(id -u | grep -o '^0$') == "0" ]]; then
    SUDO=" "
else
    SUDO="sudo"
fi

startdir=${PWD}

banner

rftw_util_version

startdir=${PWD}
if [[ -n $list ]]; then
    if [[ $list == ./* ]]; then
        flist="${startdir}/${list:2}"
    elif [[ $list == ~* ]]; then
        flist="${HOME}/${list:2}"
    elif [[ $list == /* ]]; then
        flist=$list
    else
        flist="$startdir/$list"
    fi
else
    flist=''
fi

case $opt_mode in
'r')
    if [[ -n $multi ]]; then
        if [[ ${AXIOM} == true ]]; then
            mode="multi_recon"
        fi
        multi_recon
        exit
    fi
    if [[ -n $list ]]; then
        if [[ ${AXIOM} == true ]]; then
            mode="list_recon"
        fi
        sed -i 's/\r$//' $list
        for domain in $(cat $list); do
            start
            recon
            end
        done
    else
        if [[ ${AXIOM} == true ]]; then
            mode="recon"
        fi
        start
        recon
        end
    fi
    ;;
's')
    if [[ -n $list ]]; then
        if [[ ${AXIOM} == true ]]; then
            mode="subs_menu"
        fi
        sed -i 's/\r$//' $list
        for domain in $(cat $list); do
            subs_menu
        done
    else
        subs_menu
    fi
    ;;
'p')
    if [[ -n $list ]]; then
        if [[ ${AXIOM} == true ]]; then
            mode="passive"
        fi
        sed -i 's/\r$//' $list
        for domain in $(cat $list); do
            passive
        done
    else
        passive
    fi
    ;;
'a')
    export VULNS_GENERAL=true
    if [[ -n $list ]]; then
        if [[ ${AXIOM} == true ]]; then
            mode="all"
        fi
        sed -i 's/\r$//' $list
        for domain in $(cat $list); do
            all
        done
    else
        all
    fi
    ;;
'w')
    if [[ -n $list ]]; then
        start
        if [[ $list == /* ]]; then
            cp $list "${dir}"/webs/webs.txt
        else
            cp $SCRIPTPATH/$list "${dir}"/webs/webs.txt
        fi
    else
        printf "\n\n${bred} Web mode needs a website list file as target (./reconftw.sh -l target.txt -w) ${reset}\n\n"
        exit
    fi
    webs_menu
    exit
    ;;
'n')
    PRESERVE=true
    if [[ -n $multi ]]; then
        multi_osint
        exit
    fi
    if [[ -n $list ]]; then
        sed -i 's/\r$//' $list
        while IFS= read -r domain; do
            start
            osint
            end
        done
    else
        start
        osint
        end
    fi
    ;;
'c')
    export DIFF=true
    dir="$SCRIPTPATH/Recon/$DOMAIN"
    cd $dir || {
        echo "Failed to cd directory '$dir'"
        exit 1
    }
    LOGFILE="${dir}/.log/${NOW}_${NOWT}.txt"
    called_fn_dir="${dir}"/.called_fn
    $custom_function
    cd $SCRIPTPATH || {
        echo "Failed to cd directory '$dir'"
        exit 1
    }
    exit
    ;;
    # No mode selected.  EXIT!
*)
    help
    rftw_util_tools -t "${tools}"
    exit 1
    ;;
esac
