import re


# Count number of entries in input file.
def countoccurence(reqfile, desired):

    try:
        hit_count = 0
        with open(reqfile) as f:
            for line in f:
                if re.match(desired, line):
                    hit_count = hit_count + 1
        return hit_count
    except:
        return False


# Make Directories for Batch files
def makedirs(batchnumber):
    # detect the current working directory and print it
    path = os.getcwd()
    print ("The current working directory is %s" % path)

    batchdiretory = os.path.join(path, batchnumber)

    try:
        os.mkdir(batchdiretory)
        os.mkdir(batchdirectory + '/p12')
        os.mkdir(batchdirectory + '/csr')
    except OSError:
        print ("Creation of the directory %s failed" % batchdirectory)
    else:
        print ("Successfully created the directory %s " % batchdirectory)