# This script is designed to parse the Windows LNK Files
#
# Required modules: uuid, struct, datetime, bitstring, argparse
#
# I'm using the following two URLs for reference
# https://msdn.microsoft.com/en-us/library/dd891343.aspx
# https://github.com/libyal/liblnk/blob/master/documentation/Windows%20Shortcut%20File%20(LNK)%20format.asciidoc
#
# Licensed under the GPL
# http://www.gnu.org/copyleft/gpl.html
#
# By Tom Yarrish
# Version 0.1

import uuid, struct, datetime, argparse
from bitstring import BitArray

# Parse the FILETIME data; someone else wrote this code it's not mine..but thanks!

def FromFiletime(filetime):
    if filetime < 0:
        return None
    timestamp = filetime / 10

    return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=timestamp)

# This is the function to parse the LNK Flags bitstring
# To get this to work, you do lnk_flags(bits_test.bin)

def lnk_flags(flags_to_parse):
    flags = { 0: "HasLinkTargetIDList",
             1: "HasLinkInfo",
             2: "HasName",
             3: "HasRelativePath",
             4: "HasWorkingDir",
             5: "HasArguments",
             6: "HasIconLocation",
             7: "IsUnicode",
             8: "ForceNoLinkInfo",
             9: "HasExpString",
             10: "RunInSeparateProcess",
             11: "Unused1",
             12: "HasDarwinID",
             13: "RunAsUser",
             14: "HasExpIcon",
             15: "NoPidlAlias",
             16: "Unused2",
             17: "RunWithShimLayer",
             18: "ForceNoLinkTrack",
             19: "EnableTargetMetadata",
             20: "DisableLinkPathTracking",
             21: "DisableKnownFolderTracking",
             22: "DisableKnownFolderAlias",
             23: "AllowLinkToLink",
             24: "UnaliasOnSave",
             25: "PreferEnvironmentPath",
             26: "KeepLocalIDListForUNCTarget"}

    for count, items in enumerate(flags_to_parse):
        if int(items) == 1:
            print "{} is set.".format(flags[count])
        else:
            continue
        
# This is the function to parse the attributes
# So to get this to work, you do lnk_attrib(bits_test.bin)

def lnk_attrib(attrib_to_parse):
    attrib = { 0: "FILE_ATTRIBUTE_READONLY",
              1: "FILE_ATTRIBUTE_HIDDEN",
              2: "FILE_ATTRIBUTE_SYSTEM",
              3: "Reserved1",
              4: "FILE_ATTRIBUTE_DIRECTORY",
              5: "FILE_ATTRIBUTE_ARCHIVE",
              6: "Reserved2",
              7: "FILE_ATTRIBUTE_NORMAL",
              8: "FILE_ATTRIBUTE_TEMPORARY",
              9: "FILE_ATTRIBUTE_SPARSE_FILE",
              10: "FILE_ATTRIBUTE_REPARSE_POINT",
              11: "FILE_ATTRIBUTE_COMPRESSED",
              12: "FILE_ATTRIBUTE_OFFLINE",
              13: "FILE_ATTRIBUTE_NOT_CONTENT_INDEXED",
              14: "FILE_ATTRIBUTE_ENCRYPTED" }
    
    for count, items in enumerate(attrib_to_parse):
        if int(items) == 1:
            print "{} is set.".format(attrib[count])
        else:
            continue

# This function parses the SHOWCOMMAND data

def lnk_show_win(showwin):
    if showwin == hex(0x1):
        return "SW_SHOWNORMAL"
    elif showwin == hex(0x3):
        return "SW_SHOWMAXIMIZED"
    elif showwin == hex(0x7):
        return "SW_SHOWMINNOACTIVE"
    else:
        return "SW_SHOWNORMAL (default)"

# This function parses the High Byte section of the hotkey value

def lnk_hot_key_high(hotkey_high):
    hotkey = { "0x0" : "None",
              "0x1" : "Shift",
              "0x2" : "Ctrl",
              "0x3" : "Shift + Ctrl",
              "0x4" : "Alt",
             "0x5" : "Shift + Alt", 
             "0x6" : "Ctrl + Alt" }
    bits_hotkey = BitArray(hex(hotkey_high))
    return hotkey[str(bits_hotkey)]

# This function parses out the Low Byte section of the hotkey value

def lnk_hot_key_low(hotkey):
    return chr(hotkey)

# This function parses out the hotkey data; it passes it on to two other functions

def lnk_hot_key_parse(hotkey):
    hotkey_one = lnk_hot_key_high(hotkey[1])
    hotkey_two = lnk_hot_key_low(hotkey[0])
    return hotkey_one, hotkey_two

# This function parses the LNK file header data

def lnk_file_header(header_data):
    lnk_header_size = struct.unpack("<L", header_data[0:4])
    header_clsid = header_data[4:20]
    lnk_header_clsid = uuid.UUID(bytes_le=header_clsid)
    
    # These two lines will parse out the individual bits in the flags section
    lnk_header_flags = struct.unpack("<I", header_data[20:24])
    lnk_header_flags_bits = BitArray(hex(lnk_header_flags[0]))
    
    # These two lines will parse out the individual bits for the attributes
    lnk_header_file_attrib = struct.unpack("<I", header_data[24:28])
    lnk_header_file_attrib_bits = BitArray(hex(lnk_header_file_attrib[0]))
    
    # Parse the creation time stamp
    header_creation_time = struct.unpack("<Q", header_data[28:36])
    lnk_header_creation_time = FromFiletime(header_creation_time[0])
    
    # Parse the access time stamp
    header_access_time = struct.unpack("<Q", header_data[36:44])
    lnk_header_access_time = FromFiletime(header_access_time[0])
    
    # Parse the write time stamp
    header_write_time = struct.unpack("<Q", header_data[44:52])
    lnk_header_write_time = FromFiletime(header_write_time[0])

    lnk_header_file_size = struct.unpack("<L", header_data[52:56])
    lnk_header_icon_indx = struct.unpack("<L", header_data[56:60])
    lnk_header_show_window = struct.unpack("<L", header_data[60:64])
    lnk_header_hot_key = struct.unpack("<2B", header_data[64:66])
    hot_key = lnk_hot_key_parse(lnk_header_hot_key)

    print "Header size: {} (integer: {})".format(hex(lnk_header_size[0]), lnk_header_size[0])
    print "Header CLSID: {}".format(lnk_header_clsid)
    print "\nFlags:"
    lnk_flags(lnk_header_flags_bits.bin)
    print "\nAttributes:"
    lnk_attrib(lnk_header_file_attrib_bits.bin)
    print "\nTarget Creation Time: {}".format(lnk_header_creation_time)
    print "Target Access Time: {}".format(lnk_header_access_time)
    print "Target Write Time: {}".format(lnk_header_write_time)
    print "Target File Size: {}".format(lnk_header_file_size[0])
    print "Icon Index: {}".format(lnk_header_icon_indx[0])
    print "Show Window Value: {}".format(lnk_show_win(hex(lnk_header_show_window[0])))
    print "Hot Key: {} {}".format(hot_key[0], hot_key[1])

parser = argparse.ArgumentParser()
parser.add_argument('-f', dest='lnk_file', required=True, help='LNK file to process.')
args = parser.parse_args()

with open(args.lnk_file, "rb") as lnk_file:
    lnk_file_data = lnk_file.read()
    lnk_header = lnk_file_header(lnk_file_data[:76])