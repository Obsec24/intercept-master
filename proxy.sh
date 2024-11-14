#!/bin/bash

function help {
	echo "Intercept traffic from a specified apk. Usage:"
	echo
	echo "	proxy.sh [-h] [-i <target ip>] [-a <target apk>] [-p <apk package name>]"
	echo
	echo "In case the -a options is used it is not necessary to use the -p option."
	echo "The latter should only be used if the apk is already installed."
	echo
}

function network_redirect {
	# Enable IP forwarding
	sudo sysctl -w net.ipv4.ip_forward=1
	sudo sysctl -w net.ipv6.conf.all.forwarding=1

	# Disable ICMP redirects
	sudo sysctl -w net.ipv4.conf.all.send_redirects=0

	# Redirect traffic
	sudo iptables -t nat -A PREROUTING -i eth1 -p tcp -j REDIRECT --to-port 8080
	sudo iptables -t nat -A PREROUTING -i eth1 -p tcp -j REDIRECT --to-port 8080
	sudo ip6tables -t nat -A PREROUTING -i eth1 -p tcp -j REDIRECT --to-port 8080
	sudo ip6tables -t nat -A PREROUTING -i eth1 -p tcp -j REDIRECT --to-port 8080
}

function run_mitmproxy {
	#Run proxy in another terminal
	xfce4-terminal -e "mitmdump -s ./inspect_requests.py --set app=$1"
}

unset apk
while getopts "i:a:p:h" options;
do
	case "${options}" in
		h)
			help
			exit 0
			;;
		i)
			ip=${OPTARG}
			;;
		a)
			apk=${OPTARG}
			name=$(aapt dump badging $apk | grep "package: name" | awk '{print $2}' | awk -F '=' '{print $2}' | cut -d "'" -f2)
			;;
		p)
			name=${OPTARG}
			;;
		*)
			echo "Error in one of the options"
			;;
	esac
done

run_mitmproxy $name &
network_redirect
adb connect $ip

if [ -z $apk ];
then
	exit 0
else
	adb install -r $apk
fi

