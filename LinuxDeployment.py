import os
import sys
import subprocess
import string
import random

bashfile=''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10))
bashfile='/tmp/'+bashfile+'.sh'

f = open(bashfile, 'w')
s = """#!/bin/sh
#
#
#This is for Gen6 Rescue DNS DHCP DNSMASQ Setup and create tar file to scp to new DHCP server
#
#Author - ramandap
#
#
#Pre Requirements: 
   #(1) Create working directories on puppet master (bn3phxdnspm01 - 10.64.12.18) or Rescue DNS JB

       #Example: mkdir -p /var/tmp/mywork/inputdata

   #(2) Place this script to your working directory here. 

       #Example: /var/tmp/mywork/

   #(3) Place or Create "rackmanager.<DC CODE>.conf" file ${PWD}/inputdata direcotry with the output from "sh manager info" from Rack Manager

       #EXAMPLE: /var/tmp/mywork/inputdata/rackmanager.mnz20.conf
       ##mnz20
       #| 3  |     ON     |   True   |   Server  | 84:57:33:0D:08:39  | 50d1e16f-9239-465a-9f0b-1f0b7a5f03e1 |     Success    
       #| 4  |     ON     |   True   |   Server  | 84:57:33:0D:08:A9  | 1ad5ebe4-8102-4892-9ebe-1ebe783a23d7 |     Success    

  #(4) Place or Create "gen6-netdev.conf" file ${PWD}/inputdata direcotry, with '#<DC Code>azrrdns', VLAN ID, Subnet Info and GW=<FE Gateway IP>

      #Example: /var/tmp/mywork/inputdata/gen6-netdev.conf
      ##MNZ20
      #101 13.106.206.128/26:FE GW=13.106.206.129
      #401 10.78.91.1/26:BE GW=10.78.91.1
#
red='\\e[1;31m%s\\e[0m\\n'
green='\\e[1;32m%s\\e[0m\\n'
yellow='\\e[1;33m%s\\e[0m\\n'
blue='\\e[1;34m%s\\e[0m\\n'
magenta='\\e[1;35m%s\\e[0m\\n'
cyan='\\e[1;36m%s\\e[0m\\n'
bld=$(tput bold)
nrml=$(tput sgr0)
if [ $# -gt 3 ]
then
        printf " \\n"
        printf "${bld} Invalid Input! ${nrml} \\n"
        printf " \\n"
        printf "USAGE: \\n"
        printf " \\n"
        printf "${bld} $0 <DC name> <Starting BEIP> <Starting FEIP> ${nrml} \\n"
        printf " \\n"
        #printf "EXAMPLE: \\n"
        printf " \\n"
        printf "${bld} $0 mnz20 10 140 ${nrml} \\n"
        printf " \\n"
        exit 1
fi
printf " \\n"
printf "${bld} DC Name: (%s): ${nrml}"
read input
host=${input}
    if [ `ls -al ${PWD}/inputdata/*$host* | wc -l` -ne  "1" ]
    then
     printf " \\n"
     printf "${bld} Invalid Input Data, please check ${PWD}/inputdata/ for input file for DC $host ${nrml} \\n"
     printf " \\n"
     printf "${bld} Please check ${PWD}/inputdata/ for ONE input file per DC $host ${nrml} \\n"
     printf " \\n"
     printf "${bld} Example for DC:$host, the file should be ${PWD}/inputdata/rackmanager.mnz20.conf ${nrml} \\n"
     printf " \\n"
     exit 1
     fi
input="${PWD}/inputdata"
mkdir -p $input
rmmacs=$input/rackmanager.$host.conf
vlaninfo=$input/gen6-netdev.conf
wrkspc=${PWD}/.wrkspc
mkdir -p $wrkspc
macfl=$wrkspc/.macfl
befl=$wrkspc/.befl
bgwfl=$wrkspc/.bgwfl
hostfl=$wrkspc/.hostfl
fefl=$wrkspc/.fefl
fgwfl=$wrkspc/.fgwfl
grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}' $rmmacs > $macfl
numblades=`cat $macfl | wc -l`
endip=`expr $beginip + $numblades - 1`
feendip=`expr $febeginip + $numblades - 1`
beip=`grep -A2 -i $host $vlaninfo | grep -i BE | awk '{print $2}' | cut -d'/' -f1`
begw=`grep -A2 -i $host $vlaninfo | grep -i BE | awk '{print $3}' | cut -d'=' -f2`
feip=`grep -A2 -i $host $vlaninfo | grep -i FE | awk '{print $2}' | cut -d'/' -f1`
fegw=`grep -A2 -i $host $vlaninfo | grep -i FE | awk '{print $3}' | cut -d'=' -f2`
lstoct=`echo "$beip" | sed 's/^.*\\.\\([^.]*\\)$/\\1/'`
felstoct=`echo "$feip" | sed 's/^.*\\.\\([^.]*\\)$/\\1/'`
bgnip=`expr $lstoct + 10`
febgnip=`expr $felstoct + 10`
backendip=`echo $beip | sed 's/\\.[0-9]*$//'`
frontendip=`echo $feip | sed 's/\\.[0-9]*$//'`
strip=`echo "$backendip.$bgnip"`
fesrtip=`echo "$frontendip.$febgnip"`
endip=`expr $bgnip + $numblades - 1`
feendip=`expr $febgnip + $numblades - 1`
# user="USER INPUT"
beginip=`echo $strip`
printf "${bld} Enter Starting BE IP Address for frist node:  (%s): ${nrml}" "$beginip"
read input
idnsudpvsname=${input:-$beginip}
#read -p "${bld} Enter Starting BE IP Address for frist node:  ${nrml}" idnsudpvsname
febeginip=`echo $fesrtip`
printf "${bld} Enter Starting FE IP Address for frist node:  (%s): ${nrml}" "$febeginip"
read input
idnstcpvsname=${input:-$febeginip}
#read -p "${bld} Enter Starting FE IP Address for frist node:  ${nrml}" idnstcpvsname
begw=`echo $begw`
printf "${bld} Enter BE Gateway IP:  (%s): ${nrml}" "$begw"
read input
idnsudpsgname=${input:-$begw}
#read -p "${bld} Enter BE Gateway IP:  ${nrml}" idnsudpsgname
fegw=`echo $fegw`
printf "${bld} Enter FE Gateway IP:  (%s): ${nrml}" "$fegw"
read input
idnstcpsgname=${input:-$fegw}
printf "${bld} Enter DHCP Server IP:  (%s): ${nrml}"
read input
dhcpip=${input}
dhcpint=`echo enp175s0`
printf "${bld} Enter DHCP Server Interfacename:  (%s): ${nrml}" "$dhcpint"
read input
dhcpintname=${input:-$dhcpint}
#dhcpint=${input}
printf " \\n"
printf "${bld} CHECK: You have entered:${nrml}\\n"
printf " \\n"
printf "${bld} DC Name:$host${nrml}\\n"
printf "${bld} Starting BE IP=$beginip${nrml}\\n"
printf "${bld} Starting FE IP=$febeginip${nrml}\\n"
printf "${bld} BE Gateway=$begw${nrml}\\n"
printf "${bld} FE Gateway=$fegw${nrml}\\n"
printf "${bld} DHCP Server IP =$dhcpip ${nrml}\\n"
printf "${bld} DHCP Server Interface name = $dhcpint ${nrml}\\n"
printf " \\n"
echo -n "${bld}Do you want to proceed? [yes or no]: ${nrml} "
read yno
case $yno in
        [yY] | [yY][Ee][Ss] )

DATE=`date '+%Y%m%d.%H%M'`
printf " \\n"
printf " ############################### %s\\n"
printf " \\n"
#echo "Working on DC:$host...."
echo "Creating the PXE (DHCP/TFTP  & Apache) Server at $dhcpip for DC $host...."
printf " \\n"
#
forrange=`echo $beip | cut -d'.' -f1`
#echo $feip
#echo $forrange
ip3=`echo "$beip." | sed 's/.*= *//'`
regex=`echo $ip3 | sed 's/\\./\\\\\\./g'`
dnsmasq=dnsmasq.conf.$host
gen6srvlist=gen6serverlist.$host
> $dnsmasq
> $gen6srvlist
#echo "$BEIP:$backendip"
#echo "BEGINIP:$beginip & ENDIP:$endip"
prips $strip $backendip.$endip > $befl
prips $fesrtip $frontendip.$feendip > $fefl
> $hostfl
> $bgwfl
> $fgwfl
for hname in `seq -w 1 $numblades`
do
        echo "$host"azrrdnsrl"$hname" >> $hostfl
        echo "$begw" >> $bgwfl
        echo "$fegw" >> $fgwfl
done
#do
#       eval "var$c=$test";
#       c=$((c+1));
#done)
#echo $var
#for y in `cat macs`
#do
#       echo "$var $y"
#       c=$((c+1));
#done
printf "interface=$dhcpint %s\\n" >> $dnsmasq
printf "bind-interfaces %s\\n" >> $dnsmasq
printf "domain=phx.gbl %s\\n" >> $dnsmasq
printf " %s\\n" >> $dnsmasq
printf "dhcp-range=$dhcpint,$strip,$backendip.$endip,255.255.255.0,1h %s\\n" >> $dnsmasq
paste $macfl $befl $bgwfl $hostfl $fefl $fgwfl | while IFS="$(printf '\\t')" read -r f1 f2 f3 f4 f5 f6
do
        printf 'dhcp-host=%s\\n' "$f1,$f2,$f4" >> $dnsmasq
        printf 'dhcp-host=%s\\n' "$f1,$f2,$f3,$f4,$f5,$f6" >> $gen6srvlist
done
cp -rf $gen6srvlist /var/www/html/gen6/gen6serverlist
cp -rf $gen6srvlist /var/tmp/ipchange/gen6serverlist
cp -rf $vlaninfo /var/www/html/gen6/gen6-netdev.conf
cp -rf $vlaninfo /var/tmp/ipchange/gen6-netdev.conf
    if [ `grep -i -c $host inputdata/allracks-be-fe-inventory.conf` -eq "0" ]
    then
    printf " %s\\n"
    echo "(1). Updating all inventory list to 'allracks-be-fe-inventory.conf' in inputdata and outdir"
    printf " %s\\n"
     echo "Updating entries to append to /etc/hosts at 'etc-hosts-append.conf' in inputdata and outdir"
    printf " %s\\n"
    printf " %s\\n" >> inputdata/allracks-be-fe-inventory.conf
    printf "#$host %s\\n" >> inputdata/allracks-be-fe-inventory.conf
    printf "DHCP Server = $dhcpip %s\\n" >> inputdata/allracks-be-fe-inventory.conf
    printf " %s\\n" >> inputdata/allracks-be-fe-inventory.conf
    cat $gen6srvlist | cut -d',' -f2,3,4,5,6 >> inputdata/allracks-be-fe-inventory.conf
    printf " %s\\n" >> inputdata/etc-hosts-append.conf
    printf "#$host %s\\n" >> inputdata/etc-hosts-append.conf
    printf " %s\\n" >> inputdata/etc-hosts-append.conf
    cat $gen6srvlist | cut -d',' -f2,3,4,5,6 | cut -d',' -f1,3 | sed "s/\,/\\t/g" >> inputdata/etc-hosts-append.conf
    cp -rf inputdata/allracks-be-fe-inventory.conf outdir
    cp -rf inputdata/etc-hosts-append.conf outdir
    else
    printf " %s\\n"
    echo "(1). All inventory list 'allracks-be-fe-inventory.conf' is ALREADY updated in inputdata and outdir"
    printf " %s\\n"
    echo "Entries to append to /etc/hosts at 'etc-hosts-append.conf' is ALREADY updated in inputdata and outdir"
    printf " %s\\n"
    fi
#printf "dhcp-option=option:router,$begw %s\\n" >> $dnsmasq
printf "dhcp-option=option:dns-server,10.64.5.5,10.64.6.6 %s\\n" >> $dnsmasq
printf " %s\\n" >> $dnsmasq
printf "enable-tftp %s\\n" >> $dnsmasq
printf "tftp-root=/tftp %s\\n" >> $dnsmasq
printf "dhcp-boot=/boot/netboot/pxelinux.0,pxeserver,$dhcpip %s\\n" >> $dnsmasq
printf "dhcp-match=set:efi-x86_64,option:client-arch,7 %s\\n" >> $dnsmasq
printf "dhcp-boot=tag:efi-x86_64,boot/grub/bootx64.efi %s\\n" >> $dnsmasq
printf " %s\\n"
#
#
currdhcp=`grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" /tftp/grub.cfg | head -1`
curazrrlnx=`grep 'mirror/http/hostname' /var/www/html/azrrlinux.seed | grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(26[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" | head -1`
find /tftp -name grub.cfg -exec sed -i "s/$currdhcp/$dhcpip/g" {} \\;
currdhcpp=`grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" /var/www/iso/azrrlinux.seed | head -1`
find /var/www/html -name azrrlinux.seed -exec sed -i "s/$curazrrlnx/$dhcpip/g" {} \\;
#
#echo "Creating the PXE (DHCP/TFTP  & Apache) Server at $dhcpip for DC $host...."
outdir=`echo ${PWD}/outdir`
mkdir -p $outdir
#rm -rf $outdir/$host
mkdir -p $outdir/$host
cp -rf /tftp $outdir/$host
sleep 5
cp -rf $dnsmasq $outdir/$host
sleep 3
cp -rf inputdata/package.tar $outdir/$host
sleep 3
cp -rf  /var/www/html $outdir/$host
sleep 5
#tar -c --file=$outdir/$host/tftp"$host".tar $outdir/$host/tftp >/dev/null 2>&1
#
#tar -c --file=$outdir/$host/html."$host".tar $outdir/$host/html >/dev/null 2>&1
#
#
#tar -c --file=$outdir/$host.DHCP.tar $outdir/$host  >/dev/null 2>&1
tar -cf $outdir/$host.DHCP.tar $outdir/$host  >/dev/null 2>&1
#printf " %s\\n"
##printf "(1). For DC $host: DHCP Files Ready, scp the $outdir/$host.DHCP.tar & SetupLinuxPXE.sh for DC's $host DHCP server $dhcpip '/var/tmp' %s\\n"
#printf " %s\\n"
printf "(2). Copying the PXE setup to DHCP Server (scp $outdir/$host.DHCP.tar SetupLinuxPXE.sh serveradmin@$dhcpip:/home/serveradmin) %s\\n"
printf " %s\\n"
scp $outdir/$host.DHCP.tar SetupLinuxPXE.sh serveradmin@$dhcpip:/home/serveradmin
printf " %s\\n"
printf "(3). Read The instructions from SetupLinuxPXE.sh script to make DHCP work, that includes Linux nodes with BE interface only and T0 settings %s\\n"
printf " %s\\n"
#printf " Setting up PXE server on $dhcpip for DC $host....%s\\n"
#printf " %s\\n"
ssh -t serveradmin@$dhcpip "sudo /home/serveradmin/SetupLinuxPXE.sh $host"
printf " %s\\n"
#printf " ############################### %s\\n"
rm -rf $dnsmasq $gen6srvlist $outdir/$host

printf " %s\\n"

         ;;
        [nN] | [n|N][O|o] )
                        printf "${bld} Not proceeding, you selected not to proceed with the installation ${nrml} \\n";
                                        printf " \\n"
                                                        exit 1
        ;;
*) printf "${bld} Invalid input ${nrml} \\n"
                ;;
esac
"""
f.write(s)
f.close()
os.chmod(bashfile, 0o755)
bashcmd=bashfile
for arg in sys.argv[1:]:
  bashcmd += ' '+arg
subprocess.call(bashcmd, shell=True)
