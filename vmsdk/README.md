
# SDK for CC Trusted API in Confidential VM

In confidential VM, the trusted primitives (measurement, eventlog, quote) normally
can be accessed via device node like /dev/tpm0, sysfs etc, and different vendor
may provides the different definitions. 

This VMSDK following the CC Trusted API design
shields the difference introduced by the platform and provides user with unified usage
in the confidential virtual machine environments.

![](/docs/cc-trusted-primitives-vendor.png)

_NOTE: `VMSDK` currently supports Python, and it will provide support on Rust and Golang later._

## How to use VMSDK

VMSDK is supposed to provide trusted primitives (measurement, eventlog, quote) of CVM.
All below steps are supposed to run in a CVM, such as Intel® TD.

### Installation

`VMSDK` package is already available in PyPI. You can install the SDK simply by:

```
$ pip install cctrusted-vm
```

If you would like to run from source code. Try:

```
$ git clone https://github.com/cc-api/cc-trusted-api.git
$ cd cc-trusted-api
$ source setupenv.sh
```

### Run CLI tool

It provides 3 CLI tools for quick usage of Python VMSDK. 

- [cc_event_log_cli.py](./python/cc_event_log_cli.py): Print event log of CVM.
- [cc_imr_cli.py](./python/cc_imr_cli.py): Print algorithm and hash od Integrity Measurement Registers (IMR).
- [cc_quote_cli.py](./python/cc_quote_cli.py): Print quote of CVM.


How to run the CLI tool:

```
$ git clone https://github.com/cc-api/cc-trusted-api.git
$ cd cc-trusted-api
$ sudo su
$ source setupenv.sh
$ python3 vmsdk/python/cc_imr_cli.py
```
_NOTE: The CLI tool needs to run via root user._

Below is example output of `cc_imr_cli.py`.

![](/docs/imr-cli-output.png)


### Run Tests

It provides test cases for Python VMSDK. Run tests with below commands.

```
$ git clone https://github.com/cc-api/cc-trusted-api.git
$ cd cc-trusted-api
$ sudo su
$ source setupenv.sh
$ python3 -m pip install pytest
$ python3 -m pytest -v ./vmsdk/python/tests/test_sdk.py
```

_NOTE: The tests need to run via root user._
