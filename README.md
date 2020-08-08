# Specter Recon Tool

**NOTE:**

> Currenlty Tested on KALI 2020.2

Specter Recon Tool is a [KALI Linux](https://www.kali.org/) tool for...

#### Contents

- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
- [Configuration](#configuration)
- [Files](#files)
- [Supported Operations](#supported-operations)
- [Specter Work Directory](#specter-work-directory)
- [Developer Guide](#developer-guide)

## Prerequisites

Specter should ideally be run on [KALI Linux](https://www.kali.org/). Specter uses the following **required**
3rd-party scanning tools (that come pre-installed on KALI):

- [Nmap](https://nmap.org/) for generating a "clean target list"
- [Masscan](https://github.com/robertdavidgraham/masscan) for performing port scan operations efficiently
- [Eyewitness](https://github.com/FortyNorthSecurity/EyeWitness) for performing a web security scan

If applicable, please follow the links above for information on installing each tool.

## Getting Started

### Installing Specter

WIP

### Running Specter

WIP

## Configuration

Specter uses the [Dynaconf](https://github.com/rochacbruno/dynaconf) Python library for its configuration
parsing and validation library. This project's configuration file uses the
[TOML](https://github.com/toml-lang/toml) markup language.

Within the source code, a sample configuration file lives at path `samples/settings.sample.toml`. This sample configuration
file is copied to the [Specter Work Directory](#specter-work-directory) after running `specter init`.

## Files

After running all Specter commands, the [Specter Work Directory](#specter-work-directory) will contain many different files,
including configuration and output files. The output files include intermediary files generated between operations (e.g.
`output/xml_clean_target_list.txt` and `output/web_clean_target_list.txt`), while others are generated by `masscan` or
`eyewitness` applications.

These files can be visualized by running `specter tree`:

```
specter_workdir/
├── input/
│   ├── exclude_list.txt
│   └── target_list.txt
├── output/
│   └── test_2020-08-08_10:32:35.413068/
│       ├── hosts/
│       │   ├── 10.0.0.1.txt
│       │   ├── 10.0.0.13.txt
│       │   ├── 10.0.0.2.txt
│       │   ├── 10.0.0.3.txt
│       │   └── 10.0.0.4.txt
│       ├── ports/
│       │   ├── 10001.txt
│       │   ├── 135.txt
│       │   ├── 139.txt
│       │   ├── 20005.txt
│       │   ├── 21.txt
│       │   ├── 445.txt
│       │   ├── 5000.txt
│       │   ├── 53.txt
│       │   ├── 5357.txt
│       │   ├── 548.txt
│       │   ├── 631.txt
│       │   ├── 80.txt
│       │   ├── 8008.txt
│       │   ├── 8009.txt
│       │   ├── 8200.txt
│       │   ├── 8443.txt
│       │   ├── 9000.txt
│       │   └── 9080.txt
│       ├── web_clean_target_list.txt
│       ├── web_reports/
│       │   └── eyewitness/
│       ├── xml/
│       │   └── masscan.xml
│       └── xml_clean_target_list.txt
└── settings.toml
```

**NOTE**:

> Your Specter work will may contain different host and IP files dependending on your network configuration.

### Input Files

* `settings.toml`: Specter configuration file containing all operational settings

* `target_list.txt`: List of IPs or IP ranges to be scanned

  **NOTE**:

  > 192.168.0.1-254 will scan .1 to .254 NOTE: 192,168.0.0/24 will scan .0 to .255
* `exclude _list.txt`: List of IPs or IP ranges **NOT** to scan

### Output Files

* `init`
  * `settings.toml`: Specter configuration file containing all operational settings

* `clean_list`
  * `output/xml_clean_target_list.txt`: creates a list of IPs or IP ranges for `xml_scan` to scan with excluded IPs removed

* `xml_scan`
  * `output/web_clean_target_list.txt`: creates a list of IPs with ports `80`, `443`, `8000`, `8080`, `8443` open from `masscan.xml`
  * `output/xml/masscan.xml`: `masscan` output file
  * `output/ports/`: `<PORT>`.txt files with lists of IPs with port found open from masscan.xml
  * `output/hosts/`: `<IP>`.txt files with lists of port data found open from masscan.xml

* `web_scan`
  * `ouput/web_reports/Eyewitness`: `eyewitness` output file

## Supported Operations

* `init`: Initializes the [Specter Work Directory](#specter-work-directory). This command should always be exected first.
* `clean_list`: Generates a "clean target list" file, which enumerates the IP addresses to scan using `masscan`.
* `xml_scan`:
  * Scans the IPs from the `xml_clean_target_list.txt` file with `masscan`.
  * Creates `masscan.xml` in `ouput/xml`, `web_clean_target.list.txt` for scanning with `eyewitness`, and `output/hosts` and `output/ports` directory banner data.
* `web_scan`: Scans the "web clean target list" with `eyewitness` and writes the default output to the [Specter Work Directory](#specter-work-directory).
* `tree`: Utility command for visualizing the [Specter Work Directory](#specter-work-directory).

## Specter Work Directory

The Specter Work Directory contains all configuration and input files required by Specter to correctly invoke
`nmap`, `masscan`, and `eyewitness` CLI commands via the Python [subprocess](https://docs.python.org/3/library/subprocess.html)
library. It also contains all intermediary and 3rd-party application output files. "Intermediary" files are those
generated by Specter for feeding "clean target list files" from one application to the subsequent one. The "3rd-party application
output files" include those generated by `nmap`, `masscan` and `eyewitness`.

### Snapshotting

Snapshotting of output files allows Specter to retain a history of all output files from previously executed commands.

The Specter Work Directory uses the `[general].sitename` configuration setting along with an auto-generated timestamp to
"snapshot" the output directory. Each time `specter clean_list` is run, a new "snapshot" within the output directory is
created.

**NOTE**:

> **This snapshot is only created for the `clean_list` command.** Running `xml_scan` or `web_scan` will reference the output files
> located within the "snapshot" created by `clean_list`.

For example, running `specter init` followed by `specter clean_list` will generate the following Work Directory structure:

```
specter_workdir/
├── input/
│   ├── exclude_list.txt
│   └── target_list.txt
├── output/
│   └── test_2020-08-08_11:00:59.155506/
│       ├── hosts/
│       ├── ports/
│       ├── web_reports/
│       │   └── eyewitness/
│       ├── xml/
│       └── xml_clean_target_list.txt
└── settings.toml
```

In the example above, `test_2020-08-08_11:00:59.155506/` is the "snapshot" generated by the `clean_list` command. When the
`xml_scan` or `web_scan` commands are run, the **same directory snapshot** is used.

To create a new snapsphot, simply re-run `clean_list` which will produce an output structure similar to the following:

```
specter_workdir/
├── input/
│   ├── exclude_list.txt
│   └── target_list.txt
├── output/
│   ├── test_2020-08-08_11:00:59.155506/
│   │   ├── hosts/
│   │   ├── ports/
│   │   ├── web_reports/
│   │   │   └── eyewitness/
│   │   ├── xml/
│   │   └── xml_clean_target_list.txt
│   └── test_2020-08-08_11:03:04.874875/
│       ├── hosts/
│       ├── ports/
│       ├── web_reports/
│       │   └── eyewitness/
│       ├── xml/
│       └── xml_clean_target_list.txt
```

In the example above, 2 "snapshots" can be seen:

* `test_2020-08-08_11:00:59.155506/`
* `test_2020-08-08_11:03:04.874875/`

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
* `tox -e validate-sample-config`: Validates the sample [TOML](https://github.com/toml-lang/toml) configuration file located underneath `samples/settings.sample.toml`
