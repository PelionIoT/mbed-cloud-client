import sys
import subprocess
import re 

pal_warn = re.compile("Warning.*pal")
pal_dont_treat_as_warn = re.compile("Warning.*PAL_INSECURE")

proc = subprocess.Popen(sys.argv[1].split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

for line in proc.stdout:
    print line
    if len(pal_warn.findall(line)) > 0:
	    if not len(pal_dont_treat_as_warn.findall(line)) > 0:
			raise Exception("No Warnings Allowed in Pal")
proc.wait()
print "mbed compile returned {}".format(proc.returncode)
if not proc.returncode == 0:
    raise Exception("mbed compile failed")

