
# SDK for CC Trusted API in Confidential VM

In confidential VM, the trusted primitives (measurement, eventlog, quote) normally
can be accessed via device node like /dev/tpm0, sysfs etc, and different vendor
may provides the different definitions. 

This VMSDK following the CC Trusted API design
shields the difference introduced by the platform and provides user with unified usage
in the confidential virtual machine environments.

![](/docs/cc-trusted-primitives-vendor.png)

## Building and installing `VMSDK`

`VMSDK` currently supports Python, and it will provide support on Rust and Golang later.

### Installation for Python

`VMSDK` package is already available in PyPI. You can install the SDK simply by:

```
pip install cctrusted-vm
```

If you would like to run from source code. Try:

```
source ../setupenv.sh
```