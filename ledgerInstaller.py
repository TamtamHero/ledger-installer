#!/usr/bin/env python3

import argparse

DEFAULT_ALIGNMENT = 1024
PAGE_ALIGNMENT = 64


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def get_argparser():
    parser = argparse.ArgumentParser(description="Load an app onto the device from a hex file.")
    parser.add_argument("--targetId", help="The device's target ID (default is Ledger Blue)", type=auto_int)
    parser.add_argument("--targetVersion", help="Set the chip target version")
    parser.add_argument("--fileName", help="The application hex file to be loaded onto the device")
    parser.add_argument("--icon", help="The icon content to use (hex encoded)")
    parser.add_argument("--curve", help="""A curve on which BIP 32 derivation is locked ("secp256k1", "prime256r1", or
"ed25519"), can be repeated""", action='append')
    parser.add_argument("--path", help="""A BIP 32 path to which derivation is locked (format decimal a'/b'/c), can be
repeated""", action='append')
    parser.add_argument("--path_slip21", help="""A SLIP 21 path to which derivation is locked""", action='append')
    parser.add_argument("--appName", help="The name to give the application after loading it")
    parser.add_argument("--appFlags", help="The application flags", type=auto_int)
    parser.add_argument("--bootAddr", help="The application's boot address", type=auto_int)
    parser.add_argument("--rootPrivateKey", help="""The Signer private key used to establish a Secure Channel (otherwise
a random one will be generated)""")
    parser.add_argument("--signPrivateKey", help="Set the private key used to sign the loaded app")
    parser.add_argument("--apilevel", help="Use given API level when interacting with the device", type=auto_int)
    parser.add_argument("--delete", help="Delete the app with the same name before loading the provided one",
                        action='store_true')
    parser.add_argument("--params", help="Store icon and install parameters in a parameter section before the code",
                        action='store_true')
    parser.add_argument("--tlv", help="Use install parameters for all variable length parameters", action='store_true')
    parser.add_argument("--dataSize",
                        help="The code section's size in the provided hex file (to separate data from code, "
                             "if not provided the whole allocated NVRAM section for the application will remain "
                             "readonly.",
                        type=auto_int)
    parser.add_argument("--appVersion", help="The application version (as a string)")
    parser.add_argument("--installparamsSize",
                        help="The loaded install parameters section size (when parameters are already included within "
                             "the .hex file.",
                        type=auto_int)
    parser.add_argument("--tlvraw", help="Add a custom install param with the hextag:hexvalue encoding",
                        action='append')
    parser.add_argument("--dep", help="Add a dependency over an appname[:appversion]", action='append')

    return parser


def auto_int(x):
    return int(x, 0)


def parse_bip32_path(path, apilevel):
    import struct
    if len(path) == 0:
        return b""
    result = b""
    elements = path.split('/')
    if apilevel >= 5:
        result = result + struct.pack('>B', len(elements))
    for pathElement in elements:
        element = pathElement.split('\'')
        if len(element) == 1:
            result = result + struct.pack(">I", int(element[0]))
        else:
            result = result + struct.pack(">I", 0x80000000 | int(element[0]))
    return result


def parse_slip21_path(path):
    import struct
    result = struct.pack('>B', 0x80 | (len(path) + 1))
    result = result + b'\x00' + string_to_bytes(path)
    return result


def string_to_bytes(x):
    return bytes(x, 'ascii')


if __name__ == '__main__':
    from ledgerblue.ecWrapper import PrivateKey
    from ledgerblue.hexParser import IntelHexParser, IntelHexPrinter
    from ledgerblue.hexLoader import HexLoader
    from ledgerblue.hexLoader import *
    from ledgerblue.deployed import getDeployedSecretV2
    import struct
    import binascii
    import sys

    args = get_argparser().parse_args()

    if args.apilevel is None:
        args.apilevel = 10
    if args.targetId is None:
        args.targetId = 0x31000004
    if args.fileName is None:
        raise Exception("Missing fileName")
    if args.appName is None:
        raise Exception("Missing appName")
    if args.path_slip21 is not None and args.apilevel < 10:
        raise Exception("SLIP 21 path not supported using this API level")
    if args.appFlags is None:
        args.appFlags = 0
    if args.rootPrivateKey is None:
        privateKey = PrivateKey()
        publicKey = binascii.hexlify(privateKey.pubkey.serialize(compressed=False))
        eprint("Generated random root public key : %s" % publicKey)
        args.rootPrivateKey = privateKey.serialize()

    args.appName = string_to_bytes(args.appName)

    parser = IntelHexParser(args.fileName)
    if args.bootAddr is None:
        args.bootAddr = parser.getBootAddr()

    path = b""
    curveMask = 0xff
    if args.curve is not None:
        curveMask = 0x00
        for curve in args.curve:
            if curve == 'secp256k1':
                curveMask |= 0x01
            elif curve == 'prime256r1':
                curveMask |= 0x02
            elif curve == 'ed25519':
                curveMask |= 0x04
            else:
                raise Exception("Unknown curve " + curve)

    if args.apilevel >= 5:
        if args.path_slip21 is not None:
            curveMask |= 0x08
        path += struct.pack('>B', curveMask)
        if args.path is not None:
            for item in args.path:
                if len(item) != 0:
                    path += parse_bip32_path(item, args.apilevel)
        if args.path_slip21 is not None:
            for item in args.path_slip21:
                if len(item) != 0:
                    path += parse_slip21_path(item)
            if (args.path is None) or ((len(args.path) == 1) and (len(args.path[0]) == 0)):
                path += struct.pack('>B', 0)  # Unrestricted, authorize all paths for regular derivation
    else:
        if args.curve is not None:
            eprint("Curve not supported using this API level, ignoring")
        if args.path is not None:
            if len(args.path) > 1:
                eprint("Multiple path levels not supported using this API level, ignoring")
            else:
                path = parse_bip32_path(args.path[0], args.apilevel)

    icon = None
    if args.icon is not None:
        icon = bytearray.fromhex(args.icon)

    # prepend app's data with the icon content (could also add other various install parameters)
    printer = IntelHexPrinter(parser)

    # Use of Nested Encryption Key within the SCP protocol is mandatory for upgrades
    cleardata_block_len = None
    if args.appFlags & 2:
        # ensure data can be decoded with code decryption key without troubles.
        cleardata_block_len = 16


    class BufferExchanger:
        def __init__(self, target_in, target_out):
            self.target_in = target_in
            self.target_out = target_out

        def exchange(self, apdu):
            apdu = binascii.hexlify(apdu)
            self.target_out.write(apdu + '\n'.encode())
            self.target_out.flush()
            return bytearray.fromhex(self.target_in.readline().strip())

        def apduMaxDataSize(self):
            # ensure U2F compat
            return 256 - 10


    stdout = os.fdopen(sys.stdout.fileno(), "wb", closefd=False)
    dongle = BufferExchanger(sys.stdin, stdout)
    secret = getDeployedSecretV2(dongle, bytearray.fromhex(args.rootPrivateKey), args.targetId)
    loader = HexLoader(dongle, 0xe0, True, secret, cleardata_block_len=cleardata_block_len)

    # tlv mode does not support explicit by name removal, would require
    # a list app before to identify the hash to be removed
    if (not (args.appFlags & 2)) and args.delete:
        loader.deleteApp(args.appName)

    if args.tlv:
        # if code length is not provided, then consider the whole provided
        # hex file is the code and no data section is split
        code_length = printer.maxAddr() - printer.minAddr()
        if args.dataSize is not None:
            code_length -= args.dataSize
        else:
            args.dataSize = 0

        installparams = b""

        # express dependency
        if args.dep:
            for dep in args.dep:
                appname = dep
                appversion = None
                # split if version is specified
                if dep.find(":") != -1:
                    (appname, appversion) = dep.split(":")
                depvalue = encodelv(string_to_bytes(appname))
                if appversion:
                    depvalue += encodelv(string_to_bytes(appversion))
                installparams += encodetlv(BOLOS_TAG_DEPENDENCY, depvalue)

        # add raw install parameters as requested
        if args.tlvraw:
            for tlvraw in args.tlvraw:
                (hextag, hexvalue) = tlvraw.split(":")
                installparams += encodetlv(int(hextag, 16), binascii.unhexlify(hexvalue))

        if (not (args.appFlags & 2)) and (args.installparamsSize is None or args.installparamsSize == 0):
            # build install parameters
            # mandatory app name
            installparams += encodetlv(BOLOS_TAG_APPNAME, args.appName)
            if args.appVersion is not None:
                installparams += encodetlv(BOLOS_TAG_APPVERSION, string_to_bytes(args.appVersion))
            if icon is not None:
                installparams += encodetlv(BOLOS_TAG_ICON, bytes(icon))
            if len(path) > 0:
                installparams += encodetlv(BOLOS_TAG_DERIVEPATH, path)

            # append install parameters to the loaded file
            param_start = printer.maxAddr() + (PAGE_ALIGNMENT - (args.dataSize % PAGE_ALIGNMENT)) % PAGE_ALIGNMENT
            # only append install param section when not an upgrade as it
            # has already been computed in the encrypted and signed chunk
            printer.addArea(param_start, installparams)
            paramsSize = len(installparams)
        else:
            paramsSize = args.installparamsSize
            # split code and install params in the code
            code_length -= args.installparamsSize
        # create app
        # ensure the boot address is an offset
        if args.bootAddr > printer.minAddr():
            args.bootAddr -= printer.minAddr()

        loader.createApp(
            code_length,
            args.dataSize,
            paramsSize,
            args.appFlags,
            args.bootAddr | 1
        )
    elif args.params:
        paramsSectionContent = []
        if not args.icon is None:
            paramsSectionContent = args.icon
        # take care of aligning the parameters sections to avoid possible
        # invalid dereference of aligned words in the program nvram.
        # also use the default MPU alignment
        param_start = printer.minAddr() - len(paramsSectionContent) - (
                DEFAULT_ALIGNMENT - (len(paramsSectionContent) % DEFAULT_ALIGNMENT))
        printer.addArea(param_start, paramsSectionContent)
        # account for added regions (install parameters, icon ...)
        appLength = printer.maxAddr() - printer.minAddr()

        loader.createAppNoInstallParams(
            args.appFlags,
            appLength,
            args.appName,
            None,
            path,
            0,
            len(paramsSectionContent),
            string_to_bytes(args.appVersion)
        )
    else:
        # account for added regions (install parameters, icon ...)
        appLength = printer.maxAddr() - printer.minAddr()

        loader.createAppNoInstallParams(
            args.appFlags,
            appLength,
            args.appName,
            args.icon,
            path,
            None,
            None,
            string_to_bytes(args.appVersion)
        )

    hash = loader.load(
        0x0,
        0xF0,
        printer,
        targetId=args.targetId,
        targetVersion=args.targetVersion,
        doCRC=True
    )

    eprint("Application full hash : " + hash)

    masterPrivate = PrivateKey(bytes(bytearray.fromhex(args.signPrivateKey)))
    signature = masterPrivate.ecdsa_serialize(masterPrivate.ecdsa_sign(bytes(binascii.unhexlify(hash)), raw=True))

    eprint("Application signature: " + str(binascii.hexlify(signature)))

    if args.tlv:
        loader.commit(signature)
    else:
        loader.run(args.bootAddr - printer.minAddr(), signature)
