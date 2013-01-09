#!/usr/bin/env python

import sys
import json

def main(args):
    try:
        inputFile = open('pam_lucks')
        data = json.load(inputFile)
        inputFile.close()
    except IndexError:
        return False
    vfrom = ''
    while (vfrom == ''):
        print "from :"
        vfrom = raw_input()
        for dat in data:
            if (dat['from'] == vfrom):
                vfrom = ''
    vto = ''
    while (vto == ''):
        print "to :"
        vto = raw_input()
        for dat in data:
            if (dat['to'] == vto):
                vto = ''
    newdata = {"from": vfrom,"to": vto}
    data.append(newdata)

    outputFile = open('pam_lucks', "w")
    json.dump(data, outputFile, sort_keys = False, indent = 4)
    outputFile.close()
    return True

if __name__ == "__main__":
    sys.exit(main(sys.argv))
