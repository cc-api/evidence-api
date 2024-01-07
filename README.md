[![Python Code Scan](https://github.com/cc-api/cc-trusted-api/actions/workflows/pylint.yaml/badge.svg)](https://github.com/cc-api/cc-trusted-api/actions/workflows/pylint.yaml)
[![Document Scan](https://github.com/cc-api/cc-trusted-api/actions/workflows/doclint.yaml/badge.svg)](https://github.com/cc-api/cc-trusted-api/actions/workflows/doclint.yaml)
[![Python License Check](https://github.com/cc-api/cc-trusted-api/actions/workflows/pylicense.yaml/badge.svg)](https://github.com/cc-api/cc-trusted-api/actions/workflows/pylicense.yaml)
[![VMSDK Python Test](https://github.com/cc-api/cc-trusted-api/actions/workflows/vmsdk-test-python.yaml/badge.svg)](https://github.com/cc-api/cc-trusted-api/actions/workflows/vmsdk-test-python.yaml)

# CC Trusted API

CC Trusted API helps the diverse applications to access and process the trust states
which was represented by integrity measurement, event record, report/quote in the confidential
computing environment.

![](docs/cc-trusted-api-overview.png)

## 1. TCB Measurement

The diverse application in confidential computing could be firmware or monolithic application
in Confidential VM(CVM), micro service or macro service on Kubernetes. Although
different type application might get the trust states measured in different Trusted
Computing Base (TCB), the definition and structure of integrity measurement register and
event log follows the below specifications.

![](docs/cc-trusted-api-usage.png)
| TCB | Measured By | Specification |
| --- | -------- | ------------- |
| Initial TEE | Trusted Security Manager (TSM), such as Intel TDX module, SEV secure processor | Vendor Specification such as [Intel TDX Module 1.5 ABI Specification](https://cdrdv2.intel.com/v1/dl/getContent/733579) |
| Firmware | EFI_CC_MEASUREMENT_PROTOCOL </br> CCEL ACPI Table </br> EFI_TCG2_PROTOCOL </br> TCG ACPI Table | [UEFI Specification 2.10](https://uefi.org/specs/UEFI/2.10/38_Confidential_Computing.html#virtual-platform-cc-event-log) </br> [ACPI Specification 6.5](https://uefi.org/specs/ACPI/6.5/05_ACPI_Software_Programming_Model.html#cc-event-log-acpi-table) </br> [TCG EFI Protocol Specification](https://trustedcomputinggroup.org/resource/tcg-efi-protocol-specification/) </br> [TCG ACPI Specification](https://trustedcomputinggroup.org/resource/tcg-acpi-specification/) |
| Boot Loader | EFI_CC_MEASUREMENT_PROTOCOL </br> EFI_TCG2_PROTOCOL | Grub2/Shim |
| OS | Integrity Measurement Architecture (IMA) | [Specification](https://sourceforge.net/p/linux-ima/wiki/Home/) |
| Cloud Native | Confidential Cloud Native Primitives (CCNP) | [Repository](https://github.com/intel/confidential-cloud-native-primitives) |

## 2. Trusted Foundation

Normally Trusted Platform Module(TPM) provides root of trust for PC client platform.
In confidential computing environment, vTPM (virtual TPM) might be provided different
vendor or CSP, which root of trust should be hardened by vendor secure module. Some
vendor also provided simplified solution:

|           | Measurement Register | Event Log      | Specification |
| --------- | -------------------- | ---------      | ------------- |
| vTPM      | TPM PCR              | TCG2 Event Log | [TPM2 Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/) </br> [TCG PC Client Platform TPM Profile Specification](https://trustedcomputinggroup.org/resource/pc-client-platform-tpm-profile-ptp-specification/) </br> [TCG PC Client Platform Firmware Profile Specification](https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/) |
| Intel TDX | TDX MRTD/RTMR        | CC Event Log   | [Intel TDX Module 1.5 Base Architecture Specification](https://cdrdv2.intel.com/v1/dl/getContent/733575) </br> [Intel TDX Virtual Firmware Design Guide](https://cdrdv2.intel.com/v1/dl/getContent/733585) </br> [td-shim specification](https://github.com/confidential-containers/td-shim/blob/main/doc/tdshim_spec.md) |

![](docs/cc-trusted-foundation.png)

## 3. SDKs

The back-end SDK or service will produce the TCB measurements:

| SDK | Deployment Scenarios |
| --- | --------------- |
| Firmware SDK | Firmware Application |
| [VM SDK](https://github.com/cc-api/cc-trusted-api/tree/main/vmsdk) | Confidential Virtual Machine |
| [Confidential Cloud Native Primitives (CCNP)](https://github.com/intel/confidential-cloud-native-primitives) | Confidential Cluster/Container |

## 4. Examples

### 4.1 Enumerate the all Integrity Measurement Register

The example code is refer to [here](/vmsdk/python/cc_imr_cli.py) as follows:

```
from cctrusted import CCTrustedVmSdk

# Get total count of measurement registers, Intel TDX is 4, vTPM is 24
count = CCTrustedVmSdk.inst().get_measurement_count()
for index in range(CCTrustedVmSdk.inst().get_measurement_count()):
    # Get default digest algorithms, Intel TDX is SHA384, vTPM is SHA256
    alg = CCTrustedVmSdk.inst().get_default_algorithms()
    # Get digest object for given index and given algorithms
    digest_obj = CCTrustedVmSdk.inst().get_measurement([index, alg.alg_id])

    hash_str = ""
    for hash_item in digest_obj.hash:
        hash_str += "".join([f"{hash_item:02x}", " "])

    LOG.info("Algorithms: %s", str(alg))
    LOG.info("HASH: %s", hash_str)
```

Above code should be common for any vendor/deployment via trusted API, but following
is the example output on Intel TDX via VM SDK:

```
root@tdx-guest:/home/tdx/cc-trusted-api/vmsdk/python# python3 cc_imr_cli.py
cctrusted.cvm DEBUG    Successful open device node /dev/tdx_guest
cctrusted.cvm DEBUG    Successful read TDREPORT from /dev/tdx_guest.
cctrusted.cvm DEBUG    Successful parse TDREPORT.
cctrusted.cvm INFO     ======================================
cctrusted.cvm INFO     CVM type = TDX
cctrusted.cvm INFO     CVM version = 1.5
cctrusted.cvm INFO     ======================================
__main__ INFO     Algorithms: TPM_ALG_SHA384
__main__ INFO     HASH: c1 57 27 ca c1 f5 7d 0e 91 10 6d a1 80 b3 ea ba 72 11 66 61 e1 7b a0 55 37 73 84 3a 9b 07 2e cf a3 8c c8 03 df b5 5e 0f 87 ec 23 67 80 ad b3 a6
cctrusted.cvm INFO     ======================================
cctrusted.cvm INFO     CVM type = TDX
cctrusted.cvm INFO     CVM version = 1.5
cctrusted.cvm INFO     ======================================
__main__ INFO     Algorithms: TPM_ALG_SHA384
__main__ INFO     HASH: ee 35 46 2b 47 53 58 1b 4c 5a 53 8d c1 92 51 89 ba 9d 21 f5 19 7b 6b 15 ce 10 a6 00 fb d3 12 e0 e3 5c 2b 87 01 fc b2 17 51 82 43 3c 9b 12 b9 dc
cctrusted.cvm INFO     ======================================
cctrusted.cvm INFO     CVM type = TDX
cctrusted.cvm INFO     CVM version = 1.5
cctrusted.cvm INFO     ======================================
__main__ INFO     Algorithms: TPM_ALG_SHA384
__main__ INFO     HASH: 9a c0 ba 4e db 45 03 08 9a a4 a9 2a fe 97 cb 15 94 18 2f 44 aa e0 e5 8d 6f 90 a2 22 9c f9 a4 22 86 5d 87 35 d6 0b 87 3d 6b ec 36 41 d8 96 68 00
cctrusted.cvm INFO     ======================================
cctrusted.cvm INFO     CVM type = TDX
cctrusted.cvm INFO     CVM version = 1.5
cctrusted.cvm INFO     ======================================
__main__ INFO     Algorithms: TPM_ALG_SHA384
__main__ INFO     HASH: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

```

### 4.2 Dump Report (Intel TDX only)

The example code is refer to [here](/vmsdk/python/td_report_cli.py) or as follows:

```
from cctrusted import CCTrustedTdvmSdk

tdreport = CCTrustedTdvmSdk.inst().get_tdreport()
tdreport.dump()
```

The example output is:

```
root@tdx-guest:/home/tdx/cc-trusted-api/vmsdk/python# python3 td_report_cli.py
Successful open device node /dev/tdx_guest
Successful read TDREPORT from /dev/tdx_guest.
Successful parse TDREPORT.
======================================
CVM type = TDX
CVM version = 1.5
======================================
00000000  81 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000010  06 06 16 18 03 FF 00 01 00 00 00 00 00 00 00 00  ................
00000020  60 8D 62 36 6A E6 05 EC C3 9A 6A E3 00 31 CC 7C  `.b6j.....j..1.|
00000030  AF 69 EC 2F 76 20 6A 51 E9 30 3B 7B B5 BE 3B F7  .i./v jQ.0;{..;.
00000040  2F 69 1F C9 1F 87 E4 0C 49 27 5F 10 1F 7B 46 6F  /i......I'_..{Fo
00000050  A5 B4 AF 39 8B CB E8 09 9D 2D DF C7 96 BB 27 2B  ...9.....-....'+
00000060  07 9C 6B C9 95 6D 66 9B A9 9A 67 B1 A8 93 CA 0C  ..k..mf...g.....
00000070  60 34 B8 31 7F FB 41 FB 5E 53 B4 41 32 D8 01 2C  `4.1..A.^S.A2..,
00000080  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000090  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000000A0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000000B0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000000C0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000000D0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000000E0  16 D2 1F D9 62 52 15 AF 4A 2A 06 0B 16 A6 4D 40  ....bR..J*....M@
000000F0  05 27 20 E3 23 3E AA B4 8A D0 FA 78 68 11 7C 59  .' .#>.....xh.|Y
00000100  FF 01 03 00 00 00 00 00 00 01 06 00 00 00 00 00  ................
00000110  00 00 00 00 00 00 00 00 58 B5 55 B6 89 2D E9 96  ........X.U..-..
00000120  81 04 E1 2A 4B 60 4D 54 46 8C AC 8E 44 D8 F5 D1  ...*K`MTF...D...
00000130  80 58 07 C6 08 B4 37 6E 7E 7B EF 0D FE 5A 96 29  .X....7n~{...Z.)
00000140  BB 4B 68 59 72 FC 03 22 00 00 00 00 00 00 00 00  .KhYr.."........
00000150  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000160  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000170  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000180  00 01 06 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000190  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000001A0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000001B0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000001C0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000001D0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000001E0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000001F0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000200  00 00 00 10 00 00 00 00 E7 1A 06 00 00 00 00 00  ................
00000210  F1 96 DE 06 6C 69 E2 F9 37 8D 4D 31 6F 2D 48 53  ....li..7.M1o-HS
00000220  FB 28 56 F5 C9 B7 FB 6D 2F 4A 45 AE BD B7 14 16  .(V....m/JE.....
00000230  45 AE 30 2D 48 55 0B D0 DF 8A E0 91 5A 39 BC 2B  E.0-HU......Z9.+
00000240  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000250  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000260  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000270  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000280  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000290  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000002A0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000002B0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000002C0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000002D0  C1 57 27 CA C1 F5 7D 0E 91 10 6D A1 80 B3 EA BA  .W'...}...m.....
000002E0  72 11 66 61 E1 7B A0 55 37 73 84 3A 9B 07 2E CF  r.fa.{.U7s.:....
000002F0  A3 8C C8 03 DF B5 5E 0F 87 EC 23 67 80 AD B3 A6  ......^...#g....
00000300  EE 35 46 2B 47 53 58 1B 4C 5A 53 8D C1 92 51 89  .5F+GSX.LZS...Q.
00000310  BA 9D 21 F5 19 7B 6B 15 CE 10 A6 00 FB D3 12 E0  ..!..{k.........
00000320  E3 5C 2B 87 01 FC B2 17 51 82 43 3C 9B 12 B9 DC  .\+.....Q.C<....
00000330  9A C0 BA 4E DB 45 03 08 9A A4 A9 2A FE 97 CB 15  ...N.E.....*....
00000340  94 18 2F 44 AA E0 E5 8D 6F 90 A2 22 9C F9 A4 22  ../D....o.."..."
00000350  86 5D 87 35 D6 0B 87 3D 6B EC 36 41 D8 96 68 00  .].5...=k.6A..h.
00000360  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000370  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000380  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000390  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000003A0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000003B0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000003C0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000003D0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000003E0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000003F0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
```

Above structure is defined at [here](https://github.com/tianocore/edk2/blob/master/MdePkg/Include/IndustryStandard/Tdx.h):

![](/docs/tdreport-structure.png)

### 4.3 Dump Quote

Please note that different trusted foundation may use different quote format.

For TDX, the TD Quote format definition can be found in the spec [here](https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_TDX_DCAP_Quoting_Library_API.pdf). And TDX depends on the Quote Generation Service to generate the quote. Please reference "[Whitepaper: Linux* Stacks for Intel® Trust Domain Extensions 1.5 (4.3 Attestation)](https://www.intel.com/content/www/us/en/content-details/790888/whitepaper-linux-stacks-for-intel-trust-domain-extensions-1-5.html)" to set up the environment:

        1. Set up the host: follow 4.3.1 ~ 4.3.4.

        2. Set up the guest: follow "Approach 2: Get quote via TDG.VP.VMCALL.GETQUOTE" in "4.3.5.1 Launch TD with Quote Generation Support".

The example code is refer to [here](/vmsdk/python/cc_quote_cli.py) or as follows:

```
from cctrusted import CCTrustedVmSdk

quote = CCTrustedVmSdk.inst().get_quote(None, None, None)
if quote is not None:
    quote.dump(args.out_format == OUT_FORMAT_RAW)
```

The example output is:

```
root@tdx-guest:/home/tdx/cc-trusted-api/vmsdk/python# python3 ./cc_quote_cli.py
cctrusted.cvm DEBUG    Successful open device node /dev/tdx_guest
cctrusted.cvm DEBUG    Successful read TDREPORT from /dev/tdx_guest.
cctrusted.cvm DEBUG    Successful parse TDREPORT.
cctrusted.cvm INFO     Using report data directly to generate quote
cctrusted.cvm DEBUG    Successful open device node /dev/tdx_guest
cctrusted.cvm DEBUG    Successful get Quote from /dev/tdx_guest.
cctrusted_base.tdx.quote INFO     ======================================
cctrusted_base.tdx.quote INFO     TD Quote
cctrusted_base.tdx.quote INFO     ======================================
cctrusted_base.tdx.quote INFO     TD Quote Header:
cctrusted_base.binaryblob INFO     00000000  04 00 02 00 81 00 00 00 00 00 00 00 93 9A 72 33  ..............r3
cctrusted_base.binaryblob INFO     00000010  F7 9C 4C A9 94 0A 0D B3 95 7F 06 07 C6 0E 85 25  ..L............%
cctrusted_base.binaryblob INFO     00000020  C8 09 3C 0E A0 64 EF F1 29 6B 85 83 00 00 00 00  ..<..d..)k......
cctrusted_base.tdx.quote INFO     TD Quote Body:
cctrusted_base.binaryblob INFO     00000000  04 01 01 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
cctrusted_base.binaryblob INFO     00000010  97 90 D8 9A 10 21 0E C6 96 8A 77 3C EE 2C A0 5B  .....!....w<.,.[
cctrusted_base.binaryblob INFO     00000020  5A A9 73 09 F3 67 27 A9 68 52 7B E4 60 6F C1 9E  Z.s..g'.hR{.`o..
...
cctrusted_base.binaryblob INFO     00000230  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
cctrusted_base.binaryblob INFO     00000240  00 00 00 00 00 00 00 00                          ........
cctrusted_base.tdx.quote INFO     TD Quote Signature:
cctrusted_base.binaryblob INFO     00000000  16 1F E4 F6 8C 05 D4 8F E2 EB EB C8 32 1A CE 6C  ............2..l
cctrusted_base.binaryblob INFO     00000010  90 2A B5 EA 74 F5 4C 4D A2 6A 30 AC 5C A5 13 84  .*..t.LM.j0.\...
cctrusted_base.binaryblob INFO     00000020  3D CB A2 31 20 43 8C 38 63 3D EE D1 7F B4 9F B5  =..1 C.8c=......
...
cctrusted_base.binaryblob INFO     000010D0  44 20 43 45 52 54 49 46 49 43 41 54 45 2D 2D 2D  D CERTIFICATE---
cctrusted_base.binaryblob INFO     000010E0  2D 2D 0A 00                                      --..
```

### 4.4 Dump the event log

Following are the boot-time event log collected by [VMSDK's sample code](/vmsdk/python/cc_event_log_cli.py).
Please refer the event logs collected in container with runtime IMA part at [CCNP's sample output within Container](https://github.com/intel/confidential-cloud-native-primitives/blob/main/docs/sample-output-for-node-measurement-tool-full.txt)

```
$ python3 vmsdk/python/cc_event_log_cli.py --out-format-raw false
2024-01-06 09:16:52,646 [INFO] Total 99 of event logs fetched.
2024-01-06 09:16:52,646 [INFO] Event Log Entries:
2024-01-06 09:16:52,646 [INFO] --------------------Header Specification ID Event--------------------------
2024-01-06 09:16:52,646 [INFO] IMR               : 0
2024-01-06 09:16:52,646 [INFO] Type              : 0x3 (EV_NO_ACTION)
2024-01-06 09:16:52,646 [INFO] Event:
2024-01-06 09:16:52,647 [INFO] 00000000  53 70 65 63 20 49 44 20 45 76 65 6E 74 30 33 00  Spec ID Event03.
2024-01-06 09:16:52,647 [INFO] 00000010  00 00 00 00 00 02 00 02 01 00 00 00 0C 00 30 00  ..............0.
2024-01-06 09:16:52,647 [INFO] 00000020  00                                               .
2024-01-06 09:16:52,647 [INFO] -------------------------------Event Log Entry-----------------------------
2024-01-06 09:16:52,647 [INFO] IMR               : 0
2024-01-06 09:16:52,647 [INFO] Type              : 0x8000000B (UNKNOWN)
2024-01-06 09:16:52,647 [INFO] Algorithm_id      : 12 (TPM_ALG_SHA384)
2024-01-06 09:16:52,647 [INFO] Digest[0]:
2024-01-06 09:16:52,647 [INFO] 00000000  2E 07 0C DA 35 8B 5A A0 0F 27 CC A2 5C 47 38 1B  ....5.Z..'..\G8.
2024-01-06 09:16:52,647 [INFO] 00000010  B5 64 F4 BE 3A 84 D0 59 80 5A 73 CB BD E7 64 ED  .d..:..Y.Zs...d.
2024-01-06 09:16:52,647 [INFO] 00000020  83 41 F7 E0 99 15 B5 E7 B3 70 F9 C0 8A 74 3F BD  .A.......p...t?.
2024-01-06 09:16:52,647 [INFO] -------------------------------Event Log Entry-----------------------------
2024-01-06 09:16:52,647 [INFO] IMR               : 0
2024-01-06 09:16:52,647 [INFO] Type              : 0x8000000A (UNKNOWN)
2024-01-06 09:16:52,647 [INFO] Algorithm_id      : 12 (TPM_ALG_SHA384)
2024-01-06 09:16:52,647 [INFO] Digest[0]:
2024-01-06 09:16:52,647 [INFO] 00000000  34 4B C5 1C 98 0B A6 21 AA A0 0D A3 ED 74 36 F7  4K.....!.....t6.
2024-01-06 09:16:52,647 [INFO] 00000010  D6 E5 49 19 7D FE 69 95 15 DF A2 C6 58 3D 95 E6  ..I.}.i.....X=..
2024-01-06 09:16:52,647 [INFO] 00000020  41 2A F2 1C 09 7D 47 31 55 87 5F FD 56 1D 67 90  A*...}G1U._.V.g.
2024-01-06 09:16:52,647 [INFO] -------------------------------Event Log Entry-----------------------------
2024-01-06 09:16:52,647 [INFO] IMR               : 0
2024-01-06 09:16:52,647 [INFO] Type              : 0x80000001 (EV_EFI_VARIABLE_DRIVER_CONFIG)
2024-01-06 09:16:52,647 [INFO] Algorithm_id      : 12 (TPM_ALG_SHA384)
2024-01-06 09:16:52,647 [INFO] Digest[0]:
2024-01-06 09:16:52,648 [INFO] 00000000  CF A4 E2 C6 06 F5 72 62 7B F0 6D 56 69 CC 2A B1  ......rb{.mVi.*.
2024-01-06 09:16:52,648 [INFO] 00000010  12 83 58 D2 7B 45 BC 63 EE 9E A5 6E C1 09 CF AF  ..X.{E.c...n....
2024-01-06 09:16:52,648 [INFO] 00000020  B7 19 40 06 F8 47 A6 A7 4B 5E AE D6 B7 33 32 EC  ..@..G..K^...32.
2024-01-06 09:16:52,648 [INFO] -------------------------------Event Log Entry-----------------------------
2024-01-06 09:16:52,648 [INFO] IMR               : 0
2024-01-06 09:16:52,648 [INFO] Type              : 0x80000001 (EV_EFI_VARIABLE_DRIVER_CONFIG)
2024-01-06 09:16:52,648 [INFO] Algorithm_id      : 12 (TPM_ALG_SHA384)
2024-01-06 09:16:52,648 [INFO] Digest[0]:
2024-01-06 09:16:52,648 [INFO] 00000000  6F 2E 3C BC 14 F9 DE F8 69 80 F5 F6 6F D8 5E 99  o.<.....i...o.^.
2024-01-06 09:16:52,648 [INFO] 00000010  D6 3E 69 A7 30 14 ED 8A 56 33 CE 56 EC A5 B6 4B  .>i.0...V3.V...K
2024-01-06 09:16:52,648 [INFO] 00000020  69 21 08 C5 61 10 E2 2A CA DC EF 58 C3 25 0F 1B  i!..a..*...X.%..
2024-01-06 09:16:52,648 [INFO] -------------------------------Event Log Entry-----------------------------
2024-01-06 09:16:52,648 [INFO] IMR               : 0
2024-01-06 09:16:52,648 [INFO] Type              : 0x80000001 (EV_EFI_VARIABLE_DRIVER_CONFIG)
2024-01-06 09:16:52,648 [INFO] Algorithm_id      : 12 (TPM_ALG_SHA384)
2024-01-06 09:16:52,648 [INFO] Digest[0]:
2024-01-06 09:16:52,648 [INFO] 00000000  D6 07 C0 EF B4 1C 0D 75 7D 69 BC A0 61 5C 3A 9A  .......u}i..a\:.
2024-01-06 09:16:52,648 [INFO] 00000010  C0 B1 DB 06 C5 57 D9 92 E9 06 C6 B7 DE E4 0E 0E  .....W..........
2024-01-06 09:16:52,648 [INFO] 00000020  03 16 40 C7 BF D7 BC D3 58 44 EF 9E DE AD C6 F9  ..@.....XD......
2024-01-06 09:16:52,648 [INFO] -------------------------------Event Log Entry-----------------------------
2024-01-06 09:16:52,649 [INFO] IMR               : 0
2024-01-06 09:16:52,649 [INFO] Type              : 0x80000001 (EV_EFI_VARIABLE_DRIVER_CONFIG)
2024-01-06 09:16:52,649 [INFO] Algorithm_id      : 12 (TPM_ALG_SHA384)
2024-01-06 09:16:52,649 [INFO] Digest[0]:
2024-01-06 09:16:52,649 [INFO] 00000000  08 A7 4F 89 63 B3 37 AC B6 C9 36 82 F9 34 49 63  ..O.c.7...6..4Ic
2024-01-06 09:16:52,649 [INFO] 00000010  73 67 9D D2 6A F1 08 9C B4 EA F0 C3 0C F2 60 A1  sg..j.........`.
2024-01-06 09:16:52,649 [INFO] 00000020  2E 81 48 56 38 5A B8 84 3E 56 A9 AC EA 19 E1 27  ..HV8Z..>V.....'
2024-01-06 09:16:52,649 [INFO] -------------------------------Event Log Entry-----------------------------
2024-01-06 09:16:52,649 [INFO] IMR               : 0
2024-01-06 09:16:52,649 [INFO] Type              : 0x80000001 (EV_EFI_VARIABLE_DRIVER_CONFIG)
2024-01-06 09:16:52,649 [INFO] Algorithm_id      : 12 (TPM_ALG_SHA384)
2024-01-06 09:16:52,649 [INFO] Digest[0]:
2024-01-06 09:16:52,649 [INFO] 00000000  18 CC 6E 01 F0 C6 EA 99 AA 23 F8 A2 80 42 3E 94  ..n......#...B>.
2024-01-06 09:16:52,649 [INFO] 00000010  AD 81 D9 6D 0A EB 51 80 50 4F C0 F7 A4 0C B3 61  ...m..Q.PO.....a
2024-01-06 09:16:52,649 [INFO] 00000020  9D D3 9B D6 A9 5E C1 68 0A 86 ED 6A B0 F9 82 8D  .....^.h...j....
2024-01-06 09:16:52,649 [INFO] -------------------------------Event Log Entry-----------------------------
2024-01-06 09:16:52,649 [INFO] IMR               : 0
2024-01-06 09:16:52,649 [INFO] Type              : 0x4 (EV_SEPARATOR)
2024-01-06 09:16:52,649 [INFO] Algorithm_id      : 12 (TPM_ALG_SHA384)
2024-01-06 09:16:52,649 [INFO] Digest[0]:
2024-01-06 09:16:52,650 [INFO] 00000000  39 43 41 B7 18 2C D2 27 C5 C6 B0 7E F8 00 0C DF  9CA..,.'...~....
2024-01-06 09:16:52,650 [INFO] 00000010  D8 61 36 C4 29 2B 8E 57 65 73 AD 7E D9 AE 41 01  .a6.)+.Wes.~..A.
2024-01-06 09:16:52,650 [INFO] 00000020  9F 58 18 B4 B9 71 C9 EF FC 60 E1 AD 9F 12 89 F0  .X...q...`......
2024-01-06 09:16:52,650 [INFO] -------------------------------Event Log Entry-----------------------------
2024-01-06 09:16:52,650 [INFO] IMR               : 0
2024-01-06 09:16:52,650 [INFO] Type              : 0xA (EV_PLATFORM_CONFIG_FLAGS)
2024-01-06 09:16:52,650 [INFO] Algorithm_id      : 12 (TPM_ALG_SHA384)
2024-01-06 09:16:52,650 [INFO] Digest[0]:
2024-01-06 09:16:52,650 [INFO] 00000000  9D 80 CB B7 5A 11 4B 17 98 91 F2 AA 87 1F EF 5F  ....Z.K........_
2024-01-06 09:16:52,650 [INFO] 00000010  88 26 6B 66 91 A1 97 84 A7 C7 67 AA 05 0F 89 5E  .&kf......g....^
2024-01-06 09:16:52,650 [INFO] 00000020  F3 F7 96 FF FB E8 65 20 15 47 CC 66 35 CC 9B F6  ......e .G.f5...
2024-01-06 09:16:52,650 [INFO] -------------------------------Event Log Entry-----------------------------
2024-01-06 09:16:52,650 [INFO] IMR               : 0
2024-01-06 09:16:52,650 [INFO] Type              : 0xA (EV_PLATFORM_CONFIG_FLAGS)
2024-01-06 09:16:52,650 [INFO] Algorithm_id      : 12 (TPM_ALG_SHA384)
2024-01-06 09:16:52,650 [INFO] Digest[0]:
2024-01-06 09:16:52,650 [INFO] 00000000  95 4E 44 90 62 B3 8A 5A 90 2C 9A 9A DB E2 DD 65  .ND.b..Z.,.....e
2024-01-06 09:16:52,651 [INFO] 00000010  AB A7 D3 C1 1E EB 40 15 96 A5 42 A8 9C B0 A1 C1  ......@...B.....
2024-01-06 09:16:52,651 [INFO] 00000020  03 E8 86 18 F0 44 4D B7 BB 5E 7F 60 6C 0B 2A 61  .....DM..^.`l.*a
2024-01-06 09:16:52,651 [INFO] -------------------------------Event Log Entry-----------------------------
2024-01-06 09:16:52,651 [INFO] IMR               : 0
2024-01-06 09:16:52,651 [INFO] Type              : 0xA (EV_PLATFORM_CONFIG_FLAGS)
2024-01-06 09:16:52,651 [INFO] Algorithm_id      : 12 (TPM_ALG_SHA384)
2024-01-06 09:16:52,651 [INFO] Digest[0]:
2024-01-06 09:16:52,651 [INFO] 00000000  C9 0E 67 C6 04 8E B1 A3 54 ED 0C 09 0B FE E6 A4  ..g.....T.......
2024-01-06 09:16:52,651 [INFO] 00000010  D1 FA B8 24 3A 31 1F 64 01 BC 9B 1F C6 01 B2 FA  ...$:1.d........
2024-01-06 09:16:52,651 [INFO] 00000020  C8 E3 37 BC B8 FA 53 6F 87 AF ED 3A 2A E6 31 95  ..7...So...:*.1.
2024-01-06 09:16:52,651 [INFO] -------------------------------Event Log Entry-----------------------------
2024-01-06 09:16:52,651 [INFO] IMR               : 0
2024-01-06 09:16:52,651 [INFO] Type              : 0x80000002 (EV_EFI_VARIABLE_BOOT)
2024-01-06 09:16:52,651 [INFO] Algorithm_id      : 12 (TPM_ALG_SHA384)
2024-01-06 09:16:52,651 [INFO] Digest[0]:
2024-01-06 09:16:52,651 [INFO] 00000000  72 10 AF 19 14 5E C2 A8 E2 50 A7 FE 8E 9E EE AC  r....^...P......
2024-01-06 09:16:52,651 [INFO] 00000010  13 01 E5 24 DA AB 82 36 6C 36 BE 61 4D C3 54 02  ...$...6l6.aM.T.
2024-01-06 09:16:52,651 [INFO] 00000020  A2 89 10 1E 48 CA D6 1C 45 33 7F 2F 32 C1 4F DC  ....H...E3./2.O.
2024-01-06 09:16:52,651 [INFO] -------------------------------Event Log Entry-----------------------------
2024-01-06 09:16:52,651 [INFO] IMR               : 0
2024-01-06 09:16:52,651 [INFO] Type              : 0x80000002 (EV_EFI_VARIABLE_BOOT)
2024-01-06 09:16:52,651 [INFO] Algorithm_id      : 12 (TPM_ALG_SHA384)
2024-01-06 09:16:52,651 [INFO] Digest[0]:
2024-01-06 09:16:52,651 [INFO] 00000000  30 A3 B4 AB 8A E9 C8 7F F3 0B F7 36 6B B4 99 EC  0..........6k...
2024-01-06 09:16:52,651 [INFO] 00000010  C2 7B 98 72 9B CB 51 0A 52 77 AC B6 B1 CA E9 CB  .{.r..Q.Rw......
2024-01-06 09:16:52,652 [INFO] 00000020  07 41 20 BC F2 DC EA F3 C5 D9 88 55 D1 52 C8 BD  .A ........U.R..

...
...
...

2024-01-06 09:16:52,675 [INFO] IMR               : 2
2024-01-06 09:16:52,675 [INFO] Type              : 0xD (EV_IPL)
2024-01-06 09:16:52,675 [INFO] Algorithm_id      : 12 (TPM_ALG_SHA384)
2024-01-06 09:16:52,675 [INFO] Digest[0]:
2024-01-06 09:16:52,675 [INFO] 00000000  B0 BB 85 FF 78 9F 25 DD 63 E3 41 73 6B 94 F4 BF  ....x.%.c.Ask...
2024-01-06 09:16:52,675 [INFO] 00000010  3A CD 1C FF 1C 1D F6 0B D3 FF CA 57 89 EB 73 7D  :..........W..s}
2024-01-06 09:16:52,675 [INFO] 00000020  28 17 A3 9A F6 6D E4 66 40 13 4B FB BB 20 DA D7  (....m.f@.K.. ..
2024-01-06 09:16:52,675 [INFO] -------------------------------Event Log Entry-----------------------------
2024-01-06 09:16:52,675 [INFO] IMR               : 2
2024-01-06 09:16:52,675 [INFO] Type              : 0xD (EV_IPL)
2024-01-06 09:16:52,675 [INFO] Algorithm_id      : 12 (TPM_ALG_SHA384)
2024-01-06 09:16:52,675 [INFO] Digest[0]:
2024-01-06 09:16:52,675 [INFO] 00000000  B3 53 CF 98 33 05 9B E9 AB AD F1 80 D8 3A BE B5  .S..3........:..
2024-01-06 09:16:52,676 [INFO] 00000010  EE EE C0 08 43 B3 F2 24 76 BB 5D B0 BA 2F 43 61  ....C..$v.]../Ca
2024-01-06 09:16:52,676 [INFO] 00000020  A0 26 0A F3 46 0A EC B3 C1 24 ED A9 0B 6C A7 A2  .&..F....$...l..
2024-01-06 09:16:52,676 [INFO] -------------------------------Event Log Entry-----------------------------
2024-01-06 09:16:52,676 [INFO] IMR               : 2
2024-01-06 09:16:52,676 [INFO] Type              : 0xD (EV_IPL)
2024-01-06 09:16:52,676 [INFO] Algorithm_id      : 12 (TPM_ALG_SHA384)
2024-01-06 09:16:52,676 [INFO] Digest[0]:
2024-01-06 09:16:52,676 [INFO] 00000000  93 4A AF C9 9C B0 A7 CB 1E F8 3C 5A 1E B0 1C 31  .J........<Z...1
2024-01-06 09:16:52,676 [INFO] 00000010  D6 09 27 F0 8B 2F F7 2D 2C 05 E0 B4 66 0E D1 DD  ..'../.-,...f...
2024-01-06 09:16:52,676 [INFO] 00000020  1E 13 97 38 B3 C5 63 05 02 E6 29 E8 F5 93 D7 AF  ...8..c...).....
2024-01-06 09:16:52,676 [INFO] -------------------------------Event Log Entry-----------------------------
2024-01-06 09:16:52,676 [INFO] IMR               : 2
2024-01-06 09:16:52,676 [INFO] Type              : 0xD (EV_IPL)
2024-01-06 09:16:52,676 [INFO] Algorithm_id      : 12 (TPM_ALG_SHA384)
2024-01-06 09:16:52,676 [INFO] Digest[0]:
2024-01-06 09:16:52,676 [INFO] 00000000  FE F3 79 38 3E 77 1F ED 45 7F EC FC 71 48 E0 08  ..y8>w..E...qH..
2024-01-06 09:16:52,676 [INFO] 00000010  C9 02 34 D0 52 6B 28 26 90 C5 7C 93 80 2C C9 62  ..4.Rk(&..|..,.b
2024-01-06 09:16:52,676 [INFO] 00000020  3C 25 92 36 89 DE 1C 2F CB 62 66 9F 10 E3 E1 E1  <%.6.../.bf.....
2024-01-06 09:16:52,676 [INFO] -------------------------------Event Log Entry-----------------------------
2024-01-06 09:16:52,676 [INFO] IMR               : 2
2024-01-06 09:16:52,677 [INFO] Type              : 0xD (EV_IPL)
2024-01-06 09:16:52,677 [INFO] Algorithm_id      : 12 (TPM_ALG_SHA384)
2024-01-06 09:16:52,677 [INFO] Digest[0]:
2024-01-06 09:16:52,677 [INFO] 00000000  02 2E 47 C5 E4 9B F3 C9 34 F4 88 FC C0 73 18 48  ..G.....4....s.H
2024-01-06 09:16:52,677 [INFO] 00000010  95 50 A6 4D B6 2A A0 7C A0 44 C9 DD 9C 2A 0F F9  .P.M.*.|.D...*..
2024-01-06 09:16:52,677 [INFO] 00000020  06 37 64 1B 7C 87 BD 77 E3 38 3E 70 03 9E A0 FA  .7d.|..w.8>p....
2024-01-06 09:16:52,677 [INFO] -------------------------------Event Log Entry-----------------------------
2024-01-06 09:16:52,677 [INFO] IMR               : 2
2024-01-06 09:16:52,677 [INFO] Type              : 0xD (EV_IPL)
2024-01-06 09:16:52,677 [INFO] Algorithm_id      : 12 (TPM_ALG_SHA384)
2024-01-06 09:16:52,677 [INFO] Digest[0]:
2024-01-06 09:16:52,677 [INFO] 00000000  CB B7 09 D1 3F AF 7D 16 F1 91 75 1A E2 75 F2 2A  ....?.}...u..u.*
2024-01-06 09:16:52,677 [INFO] 00000010  00 35 03 38 9E 2E 49 0A 60 CF F7 8B EB 3C D5 46  .5.8..I.`....<.F
2024-01-06 09:16:52,677 [INFO] 00000020  22 2D 59 19 04 D5 19 87 48 7F 03 CD BD 41 E4 79  "-Y.....H....A.y
2024-01-06 09:16:52,677 [INFO] -------------------------------Event Log Entry-----------------------------
2024-01-06 09:16:52,677 [INFO] IMR               : 2
2024-01-06 09:16:52,677 [INFO] Type              : 0xD (EV_IPL)
2024-01-06 09:16:52,677 [INFO] Algorithm_id      : 12 (TPM_ALG_SHA384)
2024-01-06 09:16:52,677 [INFO] Digest[0]:
2024-01-06 09:16:52,677 [INFO] 00000000  10 B1 F8 D0 36 AE FD 32 CE 77 03 11 EA 00 42 6E  ....6..2.w....Bn
2024-01-06 09:16:52,677 [INFO] 00000010  14 7B 3D AE E3 78 DD 06 79 AE DA 81 96 3B 2C 53  .{=..x..y....;,S
2024-01-06 09:16:52,677 [INFO] 00000020  89 17 87 87 96 2C E9 EA 08 E5 57 17 01 CC E9 4A  .....,....W....J
2024-01-06 09:16:52,677 [INFO] -------------------------------Event Log Entry-----------------------------
2024-01-06 09:16:52,677 [INFO] IMR               : 2
2024-01-06 09:16:52,678 [INFO] Type              : 0xD (EV_IPL)
2024-01-06 09:16:52,678 [INFO] Algorithm_id      : 12 (TPM_ALG_SHA384)
2024-01-06 09:16:52,678 [INFO] Digest[0]:
2024-01-06 09:16:52,678 [INFO] 00000000  14 7B BD CD 07 04 D1 94 2B 21 71 A0 97 E7 B0 83  .{......+!q.....
2024-01-06 09:16:52,678 [INFO] 00000010  84 F1 06 CA C7 6F 7D 57 37 E5 FE E2 BC 2E 38 DE  .....o}W7.....8.
2024-01-06 09:16:52,678 [INFO] 00000020  DB 82 1B 91 E0 9A C1 84 B4 6B B4 DC 86 B4 A8 AF  .........k......
2024-01-06 09:16:52,678 [INFO] -------------------------------Event Log Entry-----------------------------
2024-01-06 09:16:52,678 [INFO] IMR               : 2
2024-01-06 09:16:52,678 [INFO] Type              : 0xD (EV_IPL)
2024-01-06 09:16:52,678 [INFO] Algorithm_id      : 12 (TPM_ALG_SHA384)
2024-01-06 09:16:52,678 [INFO] Digest[0]:
2024-01-06 09:16:52,678 [INFO] 00000000  F2 7A 8D DB 55 31 35 EE 80 02 57 27 75 AE 39 0B  .z..U15...W'u.9.
2024-01-06 09:16:52,678 [INFO] 00000010  1B C7 44 3E BB E1 1B 86 3C D7 9A E6 6B 20 65 CD  ..D>....<...k e.
2024-01-06 09:16:52,678 [INFO] 00000020  02 E9 8C FB 17 0B 89 71 12 98 6A 88 CD 07 1E F8  .......q..j.....
2024-01-06 09:16:52,678 [INFO] -------------------------------Event Log Entry-----------------------------
2024-01-06 09:16:52,678 [INFO] IMR               : 2
2024-01-06 09:16:52,678 [INFO] Type              : 0xD (EV_IPL)
2024-01-06 09:16:52,678 [INFO] Algorithm_id      : 12 (TPM_ALG_SHA384)
2024-01-06 09:16:52,678 [INFO] Digest[0]:
2024-01-06 09:16:52,678 [INFO] 00000000  7C 5E A1 B1 0B A6 92 15 09 0E 24 90 E1 0F 9D 2D  |^........$....-
2024-01-06 09:16:52,678 [INFO] 00000010  B5 F6 A5 B0 EB 6E 08 D3 66 CC EB 8A CB 44 78 85  .....n..f....Dx.
2024-01-06 09:16:52,678 [INFO] 00000020  72 42 22 1C F5 63 23 A4 93 D1 B3 A9 58 FA 13 7C  rB"..c#.....X..|
2024-01-06 09:16:52,678 [INFO] -------------------------------Event Log Entry-----------------------------
2024-01-06 09:16:52,678 [INFO] IMR               : 2
2024-01-06 09:16:52,678 [INFO] Type              : 0xD (EV_IPL)
2024-01-06 09:16:52,679 [INFO] Algorithm_id      : 12 (TPM_ALG_SHA384)
2024-01-06 09:16:52,679 [INFO] Digest[0]:
2024-01-06 09:16:52,679 [INFO] 00000000  F7 C7 44 59 BB 0D 16 F8 AE 24 91 18 58 87 9C 7F  ..DY.....$..X...
2024-01-06 09:16:52,679 [INFO] 00000010  CA B3 B8 AF 90 9D 81 1D 94 5E 09 F7 B1 69 77 BD  .........^...iw.
2024-01-06 09:16:52,679 [INFO] 00000020  65 A8 19 12 8D 0B 5C 88 FF 29 CB 76 F3 81 BD D6  e.....\..).v....
2024-01-06 09:16:52,679 [INFO] -------------------------------Event Log Entry-----------------------------
2024-01-06 09:16:52,679 [INFO] IMR               : 2
2024-01-06 09:16:52,679 [INFO] Type              : 0xD (EV_IPL)
2024-01-06 09:16:52,679 [INFO] Algorithm_id      : 12 (TPM_ALG_SHA384)
2024-01-06 09:16:52,679 [INFO] Digest[0]:
2024-01-06 09:16:52,679 [INFO] 00000000  8B C8 E8 C5 61 F2 7F 59 88 BE 9E 69 DA 2A 00 F6  ....a..Y...i.*..
2024-01-06 09:16:52,679 [INFO] 00000010  26 C7 D3 C7 35 F5 99 AB CF 27 F8 3C 02 53 0C A7  &...5....'.<.S..
2024-01-06 09:16:52,679 [INFO] 00000020  68 47 DC 5E 15 00 7F 49 0E 2F 41 7A 24 B2 F4 57  hG.^...I./Az$..W
2024-01-06 09:16:52,679 [INFO] -------------------------------Event Log Entry-----------------------------
2024-01-06 09:16:52,679 [INFO] IMR               : 2
2024-01-06 09:16:52,679 [INFO] Type              : 0xD (EV_IPL)
2024-01-06 09:16:52,679 [INFO] Algorithm_id      : 12 (TPM_ALG_SHA384)
2024-01-06 09:16:52,679 [INFO] Digest[0]:
2024-01-06 09:16:52,679 [INFO] 00000000  86 2A E7 97 61 53 24 FD 5C 15 3D FB FC B2 26 39  .*..aS$.\.=...&9
2024-01-06 09:16:52,679 [INFO] 00000010  12 62 85 5E D2 DB 29 69 F9 84 56 F0 DA 17 B6 AA  .b.^..)i..V.....
2024-01-06 09:16:52,679 [INFO] 00000020  1C 8A A2 E2 FE 90 BC 15 67 29 57 86 A8 3C 53 71  ........g)W..<Sq
2024-01-06 09:16:52,679 [INFO] -------------------------------Event Log Entry-----------------------------
2024-01-06 09:16:52,679 [INFO] IMR               : 2
2024-01-06 09:16:52,679 [INFO] Type              : 0xD (EV_IPL)
2024-01-06 09:16:52,679 [INFO] Algorithm_id      : 12 (TPM_ALG_SHA384)
2024-01-06 09:16:52,679 [INFO] Digest[0]:
2024-01-06 09:16:52,680 [INFO] 00000000  99 5D BF 62 86 DC 9D 47 F0 EE E0 49 A4 65 84 7B  .].b...G...I.e.{
2024-01-06 09:16:52,680 [INFO] 00000010  B1 E4 CB 1F A9 1D EF FB 00 DD E8 32 D2 E0 0B 10  ...........2....
2024-01-06 09:16:52,680 [INFO] 00000020  90 49 C0 F2 ED D6 AD 66 52 52 27 75 81 38 A6 01  .I.....fRR'u.8..
2024-01-06 09:16:52,680 [INFO] -------------------------------Event Log Entry-----------------------------
2024-01-06 09:16:52,680 [INFO] IMR               : 2
2024-01-06 09:16:52,680 [INFO] Type              : 0xD (EV_IPL)
2024-01-06 09:16:52,680 [INFO] Algorithm_id      : 12 (TPM_ALG_SHA384)
2024-01-06 09:16:52,680 [INFO] Digest[0]:
2024-01-06 09:16:52,680 [INFO] 00000000  CA C0 F0 B9 3E E7 EA A4 5E 36 CD A3 FA F3 D0 A5  ....>...^6......
2024-01-06 09:16:52,680 [INFO] 00000010  F5 FC 92 EC 4D 24 C3 AF 4A D9 58 46 69 59 8F 34  ....M$..J.XFiY.4
2024-01-06 09:16:52,680 [INFO] 00000020  B6 03 C2 11 B2 20 E5 6B E5 2B DB C3 A2 F7 4F FB  ..... .k.+....O.
2024-01-06 09:16:52,680 [INFO] -------------------------------Event Log Entry-----------------------------
2024-01-06 09:16:52,680 [INFO] IMR               : 2
2024-01-06 09:16:52,680 [INFO] Type              : 0xD (EV_IPL)
2024-01-06 09:16:52,680 [INFO] Algorithm_id      : 12 (TPM_ALG_SHA384)
2024-01-06 09:16:52,680 [INFO] Digest[0]:
2024-01-06 09:16:52,680 [INFO] 00000000  E1 42 A5 94 D9 88 FD A5 A6 5B 14 24 A4 A4 8C 2C  .B.......[.$...,
2024-01-06 09:16:52,681 [INFO] 00000010  F4 B0 36 DD 77 9D 4A E2 99 AF 45 B7 D3 3B 0B FE  ..6.w.J...E..;..
2024-01-06 09:16:52,681 [INFO] 00000020  07 A4 A9 69 D3 C0 DA 72 C2 BA 53 F9 EE EA F7 A6  ...i...r..S.....
2024-01-06 09:16:52,681 [INFO] -------------------------------Event Log Entry-----------------------------
2024-01-06 09:16:52,681 [INFO] IMR               : 2
2024-01-06 09:16:52,681 [INFO] Type              : 0xD (EV_IPL)
2024-01-06 09:16:52,681 [INFO] Algorithm_id      : 12 (TPM_ALG_SHA384)
2024-01-06 09:16:52,681 [INFO] Digest[0]:
2024-01-06 09:16:52,681 [INFO] 00000000  1C 72 F4 EF 27 22 C7 6D 2C 31 F4 E8 BC CE 20 73  .r..'".m,1.... s
2024-01-06 09:16:52,681 [INFO] 00000010  5E 41 9A BE B2 E5 75 A5 B2 2A 9D 07 77 45 03 D9  ^A....u..*..wE..
2024-01-06 09:16:52,681 [INFO] 00000020  2B D3 42 4F 7D 17 84 2D 3D B1 F9 2B 7F 8F 69 42  +.BO}..-=..+..iB
2024-01-06 09:16:52,681 [INFO] -------------------------------Event Log Entry-----------------------------
2024-01-06 09:16:52,681 [INFO] IMR               : 2
2024-01-06 09:16:52,681 [INFO] Type              : 0xD (EV_IPL)
2024-01-06 09:16:52,681 [INFO] Algorithm_id      : 12 (TPM_ALG_SHA384)
2024-01-06 09:16:52,681 [INFO] Digest[0]:
2024-01-06 09:16:52,681 [INFO] 00000000  50 A0 BF 47 9C A7 67 33 62 99 0B EE 77 CE 2E 7F  P..G..g3b...w...
2024-01-06 09:16:52,681 [INFO] 00000010  0C C6 98 EF E1 34 8B CD D3 A2 1A 16 F9 40 8C 25  .....4.......@.%
2024-01-06 09:16:52,681 [INFO] 00000020  53 A2 B0 51 45 6C DD 7D 12 32 1D D1 E1 A9 BD D4  S..QEl.}.2......
2024-01-06 09:16:52,681 [INFO] -------------------------------Event Log Entry-----------------------------
2024-01-06 09:16:52,682 [INFO] IMR               : 2
2024-01-06 09:16:52,682 [INFO] Type              : 0xD (EV_IPL)
2024-01-06 09:16:52,682 [INFO] Algorithm_id      : 12 (TPM_ALG_SHA384)
2024-01-06 09:16:52,682 [INFO] Digest[0]:
2024-01-06 09:16:52,682 [INFO] 00000000  6D 37 85 65 B6 3B E0 99 25 AB D9 3E 53 9D 9B 49  m7.e.;..%..>S..I
2024-01-06 09:16:52,682 [INFO] 00000010  BE 36 D6 20 4F 5D 48 B8 8C E2 3B 47 F1 41 FE 94  .6. O]H...;G.A..
2024-01-06 09:16:52,682 [INFO] 00000020  5D DF 4A 15 AB C0 D6 89 2D 29 52 21 87 10 2D 58  ].J.....-)R!..-X
2024-01-06 09:16:52,682 [INFO] -------------------------------Event Log Entry-----------------------------
2024-01-06 09:16:52,682 [INFO] IMR               : 2
2024-01-06 09:16:52,682 [INFO] Type              : 0xD (EV_IPL)
2024-01-06 09:16:52,682 [INFO] Algorithm_id      : 12 (TPM_ALG_SHA384)
2024-01-06 09:16:52,682 [INFO] Digest[0]:
2024-01-06 09:16:52,682 [INFO] 00000000  67 06 B3 9B 4F 9F 45 D6 25 36 88 8E F3 8F 82 89  g...O.E.%6......
2024-01-06 09:16:52,682 [INFO] 00000010  C7 84 CE 9D 79 24 80 2F 3F 80 D5 57 45 98 B4 96  ....y$./?..WE...
2024-01-06 09:16:52,682 [INFO] 00000020  D1 7E 37 FE 2D D9 1B 18 36 B7 E8 49 94 12 15 00  .~7.-...6..I....
2024-01-06 09:16:52,682 [INFO] -------------------------------Event Log Entry-----------------------------
2024-01-06 09:16:52,682 [INFO] IMR               : 2
2024-01-06 09:16:52,682 [INFO] Type              : 0xD (EV_IPL)
2024-01-06 09:16:52,682 [INFO] Algorithm_id      : 12 (TPM_ALG_SHA384)
2024-01-06 09:16:52,682 [INFO] Digest[0]:
2024-01-06 09:16:52,682 [INFO] 00000000  A9 34 7E A5 98 AA 71 A7 1B BF C5 24 05 CF C6 61  .4~...q....$...a
2024-01-06 09:16:52,683 [INFO] 00000010  05 D3 C4 D7 E8 6E 8D 11 94 98 4A 1D 05 CC 74 29  .....n....J...t)
2024-01-06 09:16:52,683 [INFO] 00000020  9A 19 F5 91 CC FD DC 49 B2 39 85 F8 DA 12 1D B3  .......I.9......
2024-01-06 09:16:52,683 [INFO] -------------------------------Event Log Entry-----------------------------
2024-01-06 09:16:52,683 [INFO] IMR               : 2
2024-01-06 09:16:52,683 [INFO] Type              : 0xD (EV_IPL)
2024-01-06 09:16:52,683 [INFO] Algorithm_id      : 12 (TPM_ALG_SHA384)
2024-01-06 09:16:52,683 [INFO] Digest[0]:
2024-01-06 09:16:52,683 [INFO] 00000000  C0 37 F5 5F 35 AB F1 87 64 43 9C 61 72 83 33 3D  .7._5...dC.ar.3=
2024-01-06 09:16:52,683 [INFO] 00000010  6C 40 D7 D9 C6 37 56 DC 87 A1 A4 9C F8 D4 91 F8  l@...7V.........
2024-01-06 09:16:52,683 [INFO] 00000020  B0 EE 2F CD D3 75 AC 27 AE C4 7D 7C AB 05 91 8B  ../..u.'..}|....
2024-01-06 09:16:52,683 [INFO] -------------------------------Event Log Entry-----------------------------
2024-01-06 09:16:52,683 [INFO] IMR               : 1
2024-01-06 09:16:52,683 [INFO] Type              : 0x80000007 (EV_EFI_ACTION)
2024-01-06 09:16:52,683 [INFO] Algorithm_id      : 12 (TPM_ALG_SHA384)
2024-01-06 09:16:52,683 [INFO] Digest[0]:
2024-01-06 09:16:52,683 [INFO] 00000000  21 4B 0B EF 13 79 75 60 11 34 48 77 74 3F DC 2A  !K...yu`.4Hwt?.*
2024-01-06 09:16:52,683 [INFO] 00000010  53 82 BA C6 E7 03 62 D6 24 CC F3 F6 54 40 7C 1B  S.....b.$...T@|.
2024-01-06 09:16:52,683 [INFO] 00000020  4B AD F7 D8 F9 29 5D D3 DA BD EF 65 B2 76 77 E0  K....)]....e.vw.
2024-01-06 09:16:52,683 [INFO] -------------------------------Event Log Entry-----------------------------
2024-01-06 09:16:52,683 [INFO] IMR               : 1
2024-01-06 09:16:52,683 [INFO] Type              : 0x80000007 (EV_EFI_ACTION)
2024-01-06 09:16:52,683 [INFO] Algorithm_id      : 12 (TPM_ALG_SHA384)
2024-01-06 09:16:52,683 [INFO] Digest[0]:
2024-01-06 09:16:52,684 [INFO] 00000000  0A 2E 01 C8 5D EA E7 18 A5 30 AD 8C 6D 20 A8 40  ....]....0..m .@
2024-01-06 09:16:52,684 [INFO] 00000010  09 BA BE 6C 89 89 26 9E 95 0D 8C F4 40 C6 E9 97  ...l..&.....@...
2024-01-06 09:16:52,684 [INFO] 00000020  69 5E 64 D4 55 C4 17 4A 65 2C D0 80 F6 23 0B 74  i^d.U..Je,...#.t
```

## 5. Contributors

<!-- spell-checker: disable -->

<!-- readme: contributors -start -->
<table>
<tr>
    <td align="center">
        <a href="https://github.com/kenplusplus">
            <img src="https://avatars.githubusercontent.com/u/31843217?v=4" width="100;" alt="kenplusplus"/>
            <br />
            <sub><b>Lu Ken</b></sub>
        </a>
    </td>
    <td align="center">
        <a href="https://github.com/intelzhongjie">
            <img src="https://avatars.githubusercontent.com/u/56340883?v=4" width="100;" alt="intelzhongjie"/>
            <br />
            <sub><b>Shi Zhongjie</b></sub>
        </a>
    </td>
    <td align="center">
        <a href="https://github.com/Ruoyu-y">
            <img src="https://avatars.githubusercontent.com/u/70305231?v=4" width="100;" alt="Ruoyu-y"/>
            <br />
            <sub><b>Ying Ruoyu</b></sub>
        </a>
    </td>
    <td align="center">
        <a href="https://github.com/wenhuizhang">
            <img src="https://avatars.githubusercontent.com/u/2313277?v=4" width="100;" alt="wenhuizhang"/>
            <br />
            <sub><b>Wenhui Zhang</b></sub>
        </a>
    </td>
    <td align="center">
        <a href="https://github.com/jyao1">
            <img src="https://avatars.githubusercontent.com/u/12147155?v=4" width="100;" alt="jyao1"/>
            <br />
            <sub><b>Jiewen Yao</b></sub>
        </a>
    </td>
    <td align="center">
        <a href="https://github.com/leyao-daily">
            <img src="https://avatars.githubusercontent.com/u/54387247?v=4" width="100;" alt="leyao-daily"/>
            <br />
            <sub><b>Le Yao</b></sub>
        </a>
    </td></tr>
<tr>
    <td align="center">
        <a href="https://github.com/dongx1x">
            <img src="https://avatars.githubusercontent.com/u/34326010?v=4" width="100;" alt="dongx1x"/>
            <br />
            <sub><b>Xiaocheng Dong</b></sub>
        </a>
    </td>
    <td align="center">
        <a href="https://github.com/hairongchen">
            <img src="https://avatars.githubusercontent.com/u/105473940?v=4" width="100;" alt="hairongchen"/>
            <br />
            <sub><b>Hairongchen</b></sub>
        </a>
    </td></tr>
</table>
<!-- readme: contributors -end -->

<!-- spell-checker: enable -->
