# SPECTER RECON TOOL 

Version 0.1

**NOTE:**

> Currenlty Tested on KALI 2020.2
> target.txt format 192.168.0.1-254 will skip all addresses in the range that end in .0 or .255
> target.txt format 192,168.0.0/24 will give the entire address range including .0 and .255

#### Contents

- [REQUIRMENTS TO EXECUTE](#requirements-to-execute)
- [MINIMUM STEPS TO EXECUTION](#minimum-steps-to-execution)
- [EXECUTION](#execution)

## REQUIRMENTS TO EXECUTE

- Must run as root for web_scan operation to work 
- Must have nmap, masscan, eyewitness installed
- Check file permissions - input files are 777, 655, 600

## MINIMUM STEPS TO EXECUTION

* step 1 - update /input/ip_list/target.txt
* step 2 - update /input/ip_list/exclude.txt
* step 3 - update /input/operation/scan.csv with your network adapter
* step 3 - set masscan_ip in /input/operation/scan.csv to an IP on the target subnet **NOT** the same as the scanning network adapter 

NOTE: If a VPN is used to scan, the VPN adapter IP must match masscan_ip and banners cannot be captured

## EXECUTION

```
sudo python3 <application> <operation> optional flags = -s <site_name.txt> -t <target_list.txt> -e <exclution_list.txt> -h <help>
sudo python3 specter.py clean_list 

sudo python3 <application> <operation> optional flags = -s <site_name.txt> -c <clean_target_list.txt>
sudo python3 specter.py port_scan 

sudo python3 <application> <operation> optional flags = -s <site_name.txt> -c <clean_target_list.txt>
sudo python3 specter.py web_scan	 
```
