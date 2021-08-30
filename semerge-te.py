#!/usr/bin/python

'''
Merge all input source policy files (*.te) into one list per src domain, so long the input lines
"allow" entry matches the src-domain(s). This creates a dictionary of lists, one per src-domain.
The lists are then merged so that to combine all lines with same src-domain/dest-domain:class into one
with a group of permissions for that combo.
Finally a list of domains (types), and classes with their action group is added as header and
the final policy source file is created as such.
'''
import glob
import readline
import re
import os
import sys, getopt

dom_class = [] # dest-domain:class list
sdomain = [] # main source types (domain), as in cmd-line entry, list
all_typz = [] # all types from all the input files
typ_attrib = [] # all typeattributes
# dictionary of sdomain lists
doal_unmrgd = {}
doal_merged = {}
doal_final = {}

def main(argv):
    global doal_unmrgd
    global dom_class
    global sdomain
    dir = ''
    output_file = ''
    sdomains = ''
    edomains = ''
    temp_f = False
    ''' We need to have input on "src-domain(s)" (types to allow an action), the input directory where the source policy files
    reside, and the output merged policy file path. An optional argument (t) is to create a temp file that contains
    the unmerged lines for all the sdomain (duplicates removed already). '''
    try:
        opts, args = getopt.getopt(argv,"hd:o:D:E:t")
    except getopt.GetoptError:
        help()
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            help()
            sys.exit()
        elif opt in ("-d"):
            dir = arg.strip()
        elif opt in ("-o"):
            output_file = arg.strip()
        elif opt in ("-D"):
            # source types (domains); mutually exclusive with "edomains"
            sdomains = arg.strip()
        elif opt in ("-E"):
            # excluded source types (domains); mutually exclusive with "sdomains"
            edomains = arg.strip()
        elif opt == '-t':
            temp_f = True
    if (len(sdomains) > 0) and (len(edomains) > 0):
        help()
        sys.exit(3)

    print ('Input dir is= ' + dir)
    print ('Output file is= ' + output_file)
    if (len(sdomains) > 0):
        sdomain = sdomains.split()
    elif (len(edomains) > 0):
        print ('Src Types(s) to exclude= ' + edomains)
        extract_src_dom(dir, edomains)
    else:
        # we need to extract all the source domains
        extract_src_dom(dir)

    if (len(sdomain) > 0):
        print ('Src Types(s)= ' + " ".join(sdomain))
    else:
        help()
        sys.exit(3)

    try:
        open(output_file, 'w').close()
    except IOError:
        print('Failure opening: ' + output_file)
        sys.exit(2)

    print("Number of Input Src Types=", len(sdomain))
    combine_func(dir)
    print("Tally Unique 'dest-type:class'=", len(dom_class))

    # put all the unmerged lines into a temp file for debug analysis
    if (temp_f):
        file = os.path.splitext(output_file)
        if (len(file[1])):
           write_outputfile(doal_unmrgd, file[0]+'_t' + file[1])
        else:
           write_outputfile(doal_unmrgd, file[0]+'_t')

    merge_func()
    create_final_list()
    write_outputfile(doal_final, output_file)
    return

def help():
    print ("script.py -i <inputdir> -o <outputfile> -D <src-domain(s)> -E <exclude-src-domain(s) [-t](create temp file)")
    print ("              -D and -E optionas are mutually exclusive")
    return

def extract_src_dom(dir, dom = ''):
    global sdomain
    esdomain = []

    if (len(dom) > 0):
        # convert to a list
        esdomain = dom.split()
    for filepath in list(glob.iglob(os.path.abspath(dir) + '/' + r'*.te')):
        try:
            fp = open(filepath, "r")
        except IOError:
            print('Failure opening input file: ' + filepath)
            sys.exit(2)
        lines = fp.read().splitlines()
        for line in lines:
            # capture all types in comment
            res = re.findall(r'^[#=]+\s+(\S+)\s+=+$', line)
            if res:
                res_str = "".join(res)
                if (len(esdomain) > 0) and res_str in esdomain:
                    continue
                elif res_str not in sdomain:
                    sdomain.append(res_str)
        fp.close()
        sdomain.sort()
    return

def combine_func(dir):
    global doal_unmrgd
    global dom_class
    global sdomain
    global all_typz
    global typ_attrib
    ''' Combine all imput *.te files lines that add an action to one of the input src-domain(s).
    Each src-domain is combined into one unmerged list to form a dictionary of lists.
    We also look for duplicate lines and remove them.
    Provide tally of processed/duplicate lines and dest-domain:class tally. '''
    doal_unmrgd.clear()
    doal_unmrgd = {a : [] for a in range(0,len(sdomain))}
    input = 0
    new_lines = []
    for filepath in list(glob.iglob(os.path.abspath(dir) + '/' + r'*.te')):
        try:
            fp = open(filepath, "r")
        except IOError:
            print('Failure opening input file: ' + filepath)
            sys.exit(2)
        lines = fp.read().splitlines()
        for line in lines:
            # bypass comments
            if is_empty_or_comment(line):
                continue
            # capture all types first
            res = re.findall(r'[\t\s]+type\s+(\S+)\s*;$', line)
            if res:
                all_typz.extend(res)
            # capture all typeattributes next
            res = re.findall(r'^typeattribute\s+(\S+)\s+(\S+)\s*;$', line)
            if res:
                # only add typeattributes if type matches one of the sdomain
                # res is a list of tuple of two elements
                if res[0][0] in sdomain:
                    # save as tuple if not already in the list
                    if res not in typ_attrib:
                        typ_attrib.extend(res)
                        input += 1
            # capture all sdomain in allow rules
            res = re.findall(r'^allow\s+(\S+)\s', line)
            if not res:
                continue
            res_str = " ".join(res)
            # this pattern is to be used for extracting and sorting class groups and their permissions
            pattern = re.compile(r'\s\{.+\};')
            if res_str in sdomain:
                for x in range(0,len(doal_unmrgd)):
                    if sdomain[x] == res_str:
                        input += 1
                        if pattern.findall(line):
                            allow_context = line.split('{')[0]
                            allow_context.strip()
                            res = re.findall(r'\{(.*?)}', line)
                            res.sort()
                            # after sorting the permissions we add the group to the new line
                            line2 = allow_context + ' ' + '{ ' + " ".join(res) + ' };'
                        else:
                            line2 = line
                        if line2 not in doal_unmrgd[x]:
                            doal_unmrgd[x].append(line)
                        else:
                            # we have a duplicate
                            found = re.search('^allow\s+(.+?)$', line)
                            print("Duplicate={}".format(found.group(1)))
                        # here we want to collect all the dest-domain:class in a new list
                        res = re.findall(r'\s+(\S+:\S+)', line)
                        if not res:
                            continue
                        res_str = " ".join(res)
                        if res_str not in dom_class:
                            dom_class.append(res_str)
        fp.close()

    for x in range(0,len(doal_unmrgd)):
        len(doal_unmrgd[x])
        filter_object = filter(lambda x: x != "", doal_unmrgd[x])
        new_lines = new_lines + list(filter_object)

    print("Tally Input Allow Statements=", input)
    print("Tally Unmerged=", (len(new_lines) + len(typ_attrib)))
    return

def merge_func():
    global doal_unmrgd
    global doal_merged
    global dom_class
    global sdomain
    global typ_attrib
    ''' Umerged list is sorted already but we want to merge lines like this, e.g.
        allow httpd_sys_script_t audisp_t:dir getattr;
        allow httpd_sys_script_t audisp_t:dir search;
    Once we hit the new dest-domain:class, e.g. next line could be:
        allow httpd_sys_script_t audisp_t:file { open read };
    At the end provide a tally of processed/merged lines. '''

    doal_merged.clear()
    doal_merged = {a : [] for a in range(0,len(sdomain))}
    merged = 0
    tally = 0
    for x in range(0,len(doal_unmrgd)):
        merge_dict = {}
        for line in doal_unmrgd[x]:
            ky = ""
            access = []
            # see if access reqs are in a group
            res = re.findall(r'\{(.*?)}', line)
            if not res:
                # access reqs not in a group
                # get dest-domain:class and access req from line
                res = re.findall(r'^allow\s+\S+\s+(\S+:\S+)\s+(\S+)\s*;', line)
                if not res:
                    print("Bad line: " + line)
                    continue
                # here we have a tuple (dest-domain:class, access)
                ky = res[0][0]
                if ky not in dom_class:
                    print("Error: " + ky + " is not in dest-domain:class list")
                    continue
                acc = res[0][1]
                if len(merge_dict) == 0 or ky not in merge_dict.keys():
                    # add dict key:value being value a list
                    access.append(acc)
                    merge_dict[ky] = access
                else:
                    # key exists, extract value (list)
                    access = merge_dict.get(ky)
                    if (acc not in access):
                        # add, basically avoiding duplicate permissions in access list
                        access.append(acc)
                        access.sort()
                        merge_dict[ky] = access
                    # this is a merge so long we are reducing the nbr of original lines
                    if len(access) == 1:
                        print("Merged={} {} {}".format("".join(sdomain[x]), ky, " ".join(access)))
                    else:
                        print("Merged={} {} {} {} {}".format("".join(sdomain[x]), ky, '{', " ".join(access), '}'))
                    merged += 1
            else:
                # access permissions in a group
                res = re.findall(r'^allow\s+\S+\s+(\S+:\S+)\s+\{(.*?)\}', line)
                if not res:
                    print("Bad line 2=" + line)
                    continue
                # here we have a tuple (dest-domain:class, access)
                ky = res[0][0]
                if ky not in dom_class:
                    print("Error 2: " + ky + " is not in dest-domain:class list")
                    continue
                acclst = (res[0][1].strip()).split()
                if len(merge_dict) == 0 or ky not in merge_dict.keys():
                    # add dict key:value being value a list
                    acclst.sort()
                    merge_dict[ky] = acclst
                else:
                    # key exists, extract value (list)
                    access = merge_dict.get(ky)
                    for acc in acclst:
                        if acc not in access:
                            access.append(acc)
                    access.sort()
                    merge_dict[ky] = access
                    # this is a merge so long we are reducing the nbr of original lines
                    print("Merged={} {} {} {} {}".format("".join(sdomain[x]), ky, '{', " ".join(access), '}'))
                    merged += 1

        # done with all lines in this src-domain[x]
        doal_merged[x].append('#============= ' + sdomain[x] + ' ==============')
        for key in merge_dict:
            tally += 1
            # extract value (list) and see if more then one
            if len(merge_dict[key]) == 1:
                # single element
                doal_merged[x].append("allow" + ' ' + sdomain[x] + ' ' + key + ' ' + "".join(merge_dict[key]) + ';')
            else:
                # list of 1+ elements
                doal_merged[x].append("allow" + ' ' + sdomain[x] + ' ' + key + ' { ' + " ".join(merge_dict[key]) + ' };')

        # add the typeattribute line for the src-domain last
        for ta in typ_attrib:
            if ta[0] == sdomain[x]:
                doal_merged[x].append('typeattribute ' + ta[0] + ' ' + ta[1] + ';')

    print("Tally Merged Lines=", tally)
    print("Tally Lines Actually Merged=", merged)
    return

def write_outputfile(dict_l, file):
    # Write a head line with the policy name/ver, and append the final list of merged lines into one file
    all_lines = []

    try:
        open(file, 'w').close()
    except IOError:
        print('Failure opening: ' + file)

    for x in range(0,len(dict_l)):
        all_lines = all_lines + dict_l[x]

    with open(file, "w") as fp:
        basename = os.path.basename(file)
        fp.write("module " + os.path.splitext(basename)[0] + " 1.0;\n\n")
        fp.write("\n".join(all_lines))
    fp.close()
    return

def is_empty_or_comment(line):
    return (None != re.search("^\s*$", line)) or (line.find('#', 0) >= 0)

def create_final_list():
    global doal_merged
    global doal_final
    global sdomain
    global all_typz
    global typ_attrib
    ''' This creates the final list which includes the "require" group lines.
    First we need to capture all types and all classes per merged list of sdomain;
    next we aggregate each class with all the permissions it needs to allow per dest-domain:class group. '''
    typz = []
    clasz = []
    save_access = []
    all_lines = []
    require_grp = []

    # two lists, one for the "require" group and one for the "allow" group
    doal_final.clear()
    doal_final = {a : [] for a in range(0,1)}
    empty = [""]
    for x in range(0,len(doal_merged)):
        filter_object = filter(lambda x: x != "", doal_merged[x])
        all_lines = all_lines + empty + list(filter_object)

    # find all types and classes
    for line in all_lines:
        # bypass comments
        if is_empty_or_comment(line):
            continue
        # here we want to collect all the dest-domain:class in a new list
        res = re.findall(r'\s+(\S+:\S+)', line)
        if not res:
            continue
        res_str = "".join(res)
        typ = res_str.split(':')[0]
        clas = res_str.split(':')[1]
        # as safety check for dummy types (such as "self") check from master list of types
        if typ not in typz and typ in all_typz:
            typz.append(typ)
        if clas not in clasz:
            clasz.append(clas)

    # remove "self" if in list
    '''
    if "self" in typz:
        typz.remove("self")'''
    # Add the sdomain to the types
    for sdom in sdomain:
        if sdom not in typz:
            typz.append(sdom)

    print("Total Type Tally={}".format(len(typz)))
    print("Total Class Tally={}".format(len(clasz)))

    # from same final list find longest string of access reqs for a class
    claz_access_dict = {}
    claz_access_dict.clear()
    claz_access_dict = {a : [] for a in range(0,len(clasz))}
    idx = 0
    for cl in clasz:
        for line in all_lines:
            if is_empty_or_comment(line):
                continue
            res = re.findall(r'\s+(\S+:\S+)', line)
            if not res:
                continue
            # we only care about the class from the dest-domain:class group
            res_str = "".join(res)
            clas = res_str.split(':')[1]
            if (cl != clas):
                continue
            # if we are here this line has same class component "cl"
            # see if access reqs are in a group
            res = re.findall(r'\{(.*?)}', line)
            if not res:
                # access reqs not in a group
                res = re.findall(r'^allow\s+\S+\s+\S+:\S+\s+(\S+)\s*;$',line)
                res_str = "".join(res)
                if not res:
                    print("Bad line 4: " + line)
                    continue
                if not claz_access_dict[idx]:
                    # save it; only none
                    claz_access_dict[idx] = res
                elif res_str not in claz_access_dict[idx]:
                    # add it to the list and keep it sorted
                    claz_access_dict[idx].extend(res)
                    claz_access_dict[idx].sort()
            else:
                # access reqs in a group
                res = re.findall(r'\{(.*?)\}', line)
                if not res:
                    print("Bad line 5: " + line)
                    continue
                # it is a single string of space-separated access reqs
                res_str = "".join(res)
                if not claz_access_dict[idx]:
                    claz_access_dict[idx] = res_str.split()
                    claz_access_dict[idx].sort()
                else:
                    # this is like a merge; i.e. add whatever is not in the list
                    for r in res_str.split():
                        if r not in claz_access_dict[idx]:
                            claz_access_dict[idx].append(r)
                    claz_access_dict[idx].sort()
        # here we exhausted all the lines for a given class_dict index and move to next class
        idx += 1

    require_grp.append('require {')
    for typ in typz:
        require_grp.append('\ttype ' + typ + ';')
    idx = 0
    # we might have something like this in the dictionary of access ists:
    #{0: ['append', 'execute', 'getattr', 'ioctl', 'open'], 1: ['noatsecure', 'rlimitinh', 'siginh'], 2: ['send_msg'], 3: ['net_admin']}
    for clas in clasz:
        if (len(claz_access_dict[idx]) == 1):
            # a single access request
            require_grp.append('\tclass ' + clas + ' ' + "".join(claz_access_dict[idx]) + ';')
        else:
            # multiple access reqs
            require_grp.append('\tclass ' + clas + ' { ' + " ".join(claz_access_dict[idx]) + ' };')
        idx += 1
    # add the attributes
    for at in typ_attrib:
        require_grp.append('\tattribute ' + at[1] + ';')
    require_grp.append('}')

    # save the first part of the dictionary
    doal_final[0] = require_grp
    # save the 2nd part of the dictionary
    doal_final[1] = all_lines
    print("Final Tally Allow Statements={}".format(len([line for line in doal_final[1] if not is_empty_or_comment(line)])))
    return

if __name__ == "__main__":
    main(sys.argv[1:])
