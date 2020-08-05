# Specter Recon Tool

**NOTE:**

> Currenlty Tested on KALI 2020.2

Specter Recon Tool is a [KALI Linux](https://www.kali.org/) tool for...

#### Contents

- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
- [Supported Operations](#supported-operations)
- [Developer Guide](#developer-guide)

## Prerequisites

Specter should ideally be run on [KALI Linux](https://www.kali.org/). Specter uses the following **required**
3rd-party scanning tools (that come pre-installed on KALI):

- [Nmap](https://nmap.org/) for generating a "clean target list"
- [Masscan](https://github.com/robertdavidgraham/masscan) for performing port scan operations efficiently
- [Eyewitness](https://github.com/FortyNorthSecurity/EyeWitness) for performing a web security scan

If applicable, please follow the links above for information on installing each tool.

## Getting Started

WIP

### Configuration

Specter uses the [Dynaconf](https://github.com/rochacbruno/dynaconf) Python library for its configuration
parsing and validation library. This project's configuration file uses the
[TOML](https://github.com/toml-lang/toml) markup language.

A sample configuration file exists underneath the relative path `samples/settings.sample.toml`.

### Input Files

* `clean_list Operation`
* `target_list.txt`: List of IPs or IP ranges to be scanned NOTE: 192.168.0.1-254 will scan .1 to .254 NOTE: 192,168.0.0/24 will scan .0 to .255
* `exclude _list.txt`: List of IPs or IP ranges NOT to scan
* `settings.toml`: Configuration file of operational settings to read in

* `xml_scan Operation`
* `xml_clean_target_list.txt`: List of IPs or IP ranges to scan with excluded IPs removed
* `settings.toml`: Configuration file of operational settings to read in

* `web_scan Operation`
* `web_clean_target.list.txt`: List of IPs with ports 80,443,8000,8080,8443 open from `masscan.xml`
* `settings.toml`: Configuration file of operational settings to read in 

### Output Files

* `clean_list Operation`
* `input/xml_clean_target_list.txt`: creates a list of IPs or IP ranges to scan with excluded IPs removed

* `xml_scan Operation`
* `output/xml/masscan.xml`: masscan output file saved to output/xml
* `output/ports/`: port.txt files with lists of IPs with port found open from masscan.xml
* `output/hosts/`: IP.txt files with lists of port data found open from masscan.xml

* `web_scan Operation`
* `ouput/web_reports/Eyewitness`: masscan output file saved to output/xml

## Supported Operations

* `clean_list`: Generates a "clean target list" file, which enumerates the IP addresses to scan using `masscan`
* `xml_scan`: Scans the IPs from the `xml_clean_target_list.txt` file with `masscan`. Creats `masscan.xml` in ouput/xml, `web_clean_target.list.txt` for scanning with `eyewitness`, output/host and output/ports directory banner data 
* `web_scan`: Scans the "web clean target list" with `eyewitness` and creates defaut output 

## Developer Guide

### Dev Environment - Setup

1. Install Python 3: https://www.python.org/downloads/
2. Install `pip`: https://pip.pypa.io/en/stable/installing/
3. Install `tox` using `pip` by running `pip install tox` in your terminal

### Dev Environment - Running Specter CLI

To run any of the [Supported Operations](#supported-operations), use `tox` as the entrypoint:

```
tox -e specter -- <COMMAND>
```

Examples:

* To run `clean_list`:

  > tox -e specter -- clean_list

* To run `xml_scan`:

  > tox -e specter -- xml_scan

* To run `web_scan`:

  > tox -e specter -- web_scan

### Dev Environment - Tools

This project makes use of [tox](https://tox.readthedocs.io/en/latest/) to facilitate testing for developers.
The following tox commands can be used:

* `tox -e fmt`: Formats the Python project code using the Google linter tool, [yapf](https://github.com/google/yapf)
* `tox -e lint`: Checks that the Python project code passes `yapf` linter checks
* `tox -e validate-config <CONFIG_FILE_PATH>`: Validates the [TOML](https://github.com/toml-lang/toml) configuration file specified by `<CONFIG_FILE_PATH>`
* `tox -e validate-sample-config`: Validates the sample [TOML](https://github.com/toml-lang/toml) configuration file located underneath `samples/settings.sample.toml`
