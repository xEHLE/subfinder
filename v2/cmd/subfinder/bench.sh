#!/bin/sh

echo "::group::Build Subfinder"
go build .
echo "::endgroup::"

echo "::group::Setup Targets"

targetcount=( "1" "5" "10" "25" "50" )
mkdir targets

for i in ${targetcount[@]};
do
  echo "[+] Run Subdomain Enumeration using old subfinder with $i targets";
  cmdutil ./subfinder -dL targets/target_$i.txt -s waybackarchive,anubis,alienvault,crtsh,dnsdumpster -v -timeout 300 -max-time 15 -c 500
done
