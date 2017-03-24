#!/usr/bin/env python
"""
This script uses Volatility Framework to open memory samples and look for possible
processes that do not have a correspondent parent. This is a suspicious behavior and
can indicate the presence of malware.
"""
import volatility.conf as conf
import volatility.registry as registry
import volatility.commands as commands
import volatility.addrspace as addrspace
import volatility.plugins.taskmods as taskmods
from cStringIO import StringIO
import sys

registry.PluginImporter()
config = conf.ConfObject()
registry.register_global_options(config, commands.Command)
registry.register_global_options(config, addrspace.BaseAddressSpace)
config.parse_options()
config.PROFILE="WinXPSP3x86"
config.LOCATION = file:///winxpsp3.vmem

class Capturing(list):
    def __enter__(self):
        self._stdout = sys.stdout
        sys.stdout = self._stringio = StringIO()
        return self
    def __exit__(self, *args):
        self.extend(self._stringio.getvalue().splitlines())
        sys.stdout = self._stdout

# Staging the output variable
with Capturing() as big_output:
    print ''

"""
Acquiring the process list (with headers)
The execute() method lists the whole process list obtained from
memory image.
"""

# The execute()'s output will be put inside big_output variable
with Capturing(big_output) as big_output:  
    p.execute()

# Removing big_output's headers
small_output = big_output[3:]

# Acquiring PIDs and PPIDs
pid = list()
ppid = list()
for line in small_output:
    pid.append(line.split()[2]) # Getting PID
    ppid.append(line.split()[3]) # Getting PID

"""
This particular memory sample contains Shylock malware.
Besides other features, it creates a ghost process that spawns other ones, such as explorer.exe.
So, we need to look for PIDs not having corresponding PPIDs.
Of course, 'System' process is an exception since it's the first one to be started,
such as 'init' on Unix/Linux systems.
"""
# Looking for an "orphan" PPID inside PID list
suspicious = list()
for process in ppid:
    try:
        found = pid.index(process)
    except:
        # We need to populate the PIDs of suspicious processes
        # Exception is "System" (PID 0)
        if process != "0":
            suspicious.append(process)

# Presenting eventual suspicious PIDs.
if len(suspicious) > 0:
     print "You should investigate the following processes:"
     for line in suspicious:
         print "PID: ", line
