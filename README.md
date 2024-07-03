# revShell

<p align="center">
  <img src="#" alt="revShell" width="400">
</p>

## Description

**revShell** is a powerful and versatile tool for generating various types of reverse shells in multiple programming languages. This tool facilitates the quick and efficient generation of reverse shell commands, providing different methods and options for various situations and environments.

## Features

`revShell` supports the generation of reverse shells in the following languages ​​and environments:

- **PHP**: Use different methods such as `exec`, `shell_exec`, `system`, `passthru`, `popen`, `proc_open`.
- **PowerShell**: Provides multiple variants, including TLS encrypted connections.
- **Python**: Compatible with versions 2.x and 3.x, using sockets and `pty`.
- **Ruby**: Shells with and without use of `sh`.
- **socat**: With TTY support.
- **SQLite3 and netcat**: Combined use to create reverse shells.
- **node.js**: Using the `child_process` module.
- **Groovy**: Uses sockets and `ProcessBuilder`.
- **telnet**: Reverse shell using `telnet`.
- **zsh**: Using `zmodload` and `ztcp`.
- **Lua**: With `socket` and `os` modules.
- **Golang**: Reverse shell using `net` and `os/exec`.
- **Vlang**: Using `os.system`.
- **Awk**: Using inet sockets.
- **Dart**: Using `dart:io` and `dart:convert`.
- **Crystal**: Using `process` and `socket`.

## Installation

To install and configure `revShell`, follow the steps below:

### Clone the Repository

```bash
git clone https://github.com/D1se0/revShell.git
cd revShell
```

### Run the Requirements Script

The requirements.sh script will install all the necessary dependencies and configure the tool so that it can be used from anywhere in the terminal.

```bash
sudo ./requirements.sh
```

### Verify Installation

After running the requirements script, verify that the tool is installed correctly:

```bash
revShell -h
```
or from the `.py` script

```bash
python3 revShell.py -h
```

## Use

`revShell` is extremely easy to use. Below are some examples of how to generate different types of reverse shells.

```bash
python3 revShell.py -i <HOST_IP> -p <PORT> -t <FORMAT>
```

### Examples

Generate a Reverse Shell in bash:

```bash
python3 revShell.py -i 10.10.11.11 -p 7777 -t 'bash -i'
```

Generate a Reverse Shell in PHP:

```bash
python3 revShell.py -i 10.10.11.11 -p 7777 -t 'PHP proc_open'
```

Generate a Reverse Shell in PowerShell:

```bash
python3 revShell.py -i 10.10.11.11 -p 7777 -t 'PowerShell #1'
```

Generate a Reverse Shell in Python:

```bash
python3 revShell.py -i 10.10.11.11 -p 7777 -t 'Python #1'
```

Generate a Reverse Shell in Ruby:

```bash
python3 revShell.py -i 10.10.11.11 -p 7777 -t 'Ruby #1'
```

Other options:

`revShell` supports many more options and languages. To see all available options:

```bash
python3 revShell.py -fh
```

## Contributions

Contributions are welcome. Please submit a pull request or open an issue to discuss the changes you would like to make.

## License

This project is licensed under the terms of the MIT License.
