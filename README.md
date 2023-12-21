[![Python Code Scan](https://github.com/cc-api/cc-trusted-api/actions/workflows/pylint.yaml/badge.svg)](https://github.com/cc-api/cc-trusted-api/actions/workflows/pylint.yaml)
[![Document Scan](https://github.com/cc-api/cc-trusted-api/actions/workflows/doclint.yaml/badge.svg)](https://github.com/cc-api/cc-trusted-api/actions/workflows/doclint.yaml)
[![Python License Check](https://github.com/cc-api/cc-trusted-api/actions/workflows/pylicense.yaml/badge.svg)](https://github.com/cc-api/cc-trusted-api/actions/workflows/pylicense.yaml)
# CC Trusted API

CC Trusted API helps the diverse applications to access and process the trust states
which was represented by integrity measurement, event record, report/quote in the confidential
computing environment.

![](docs/cc-trusted-api-overview.png)

## 1. TCB Measurement

The diverse application in confidential computing could be firmware or monolithic application
in Confidential VM(CVM), micro service or macro service on Kubernetes. Although
different type application might get the trust states measured in different Trusted
Computing Base (TCB), but the definition and structure of integrity measurement,
event record follows [TCG PC Client Platform Firmware Profile Specification](https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClient_PFP_r1p05_v23_pub.pdf)

![](docs/cc-trusted-api-usage.png)
| TCB | Measured By | Specification |
| --- | -------- | ------------- |
| TEE | Vendor Secure Module like Intel TDX module, SEV secure processor | Vendor Specification like [Intel TDX Module Specification](https://cdrdv2-public.intel.com/733575/intel-tdx-module-1.5-base-spec-348549002.pdf) |
| Firmware | [EFI_CC_MEASUREMENT_PROTOCOL](https://github.com/tianocore/edk2/blob/master/MdePkg/Include/Protocol/CcMeasurement.h) | [UEFI Specification 2.10](https://uefi.org/specs/UEFI/2.10/) |
| Boot Loader | [EFI_CC_MEASUREMENT_PROTOCOL](https://github.com/tianocore/edk2/blob/master/MdePkg/Include/Protocol/CcMeasurement.h) | Grub2/Shim |
| OS | Integrity Measurement Architecture (IMA) | [Specification](https://sourceforge.net/p/linux-ima/wiki/Home/) |
| Cloud Native | Confidential Cloud Native Primitives (CCNP) | [Repository](https://github.com/intel/confidential-cloud-native-primitives) |

## 2. Trusted Foundation

Normally Trusted Platform Module(TPM) provides root of trust for PC client platform.
In confidential computing environment, vTPM (virtual TPM) might be provided different
vendor or CSP, which root of trust should be hardened by vendor secure module. Some
vendor also provided simplified solution:

|    | Intel | vTPM |
| --- | --- | --- |
| Integrity Measurement Register | RTMR/MRTD | PCR |
| Event Log ACPI table | CCEL | TPM2 |

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

### 4.2 Print Report (Intel TDX only)

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

### 4.3 Print Quote

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
