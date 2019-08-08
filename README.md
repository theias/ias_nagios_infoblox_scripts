# ias-nagios-infoblox-scripts

At IAS we use Nagios and Infoblox.  We use extensible attributes in Infoblox
to denote which hosts should be monitored, and how, by Nagios.

# Repository

The current repository for this script is:

* https://github.com/theias/ias_nagios_infoblox_scripts

# License

copyright (C) 2017 Christopher Peterson, Institute for Advanced Study

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

See 

* http://www.gnu.org/licenses/

## Description

*  nagios_hosts_from_ipam.py - This script looks for host records and CNAMES that have
"nagios_notify" set to 1.  It then dumps a json document containing that data

# Supplemental Documentation

Supplemental documentation for this project can be found here:

* [Supplemental Documentation](./doc/index.md)

# Installation

Ideally stuff should run if you clone the git repo, and install the deps specified
in either "deb_control" or "rpm_specific"

Optionally, you can build a package which will install the binaries in

* /opt/IAS/bin/ias-nagios-infoblox-scripts/

# Building a Package

This build process uses fakeroot.

## "Automation Permissions"

If you don't have the users present on your system that the process uses for
permissions, you will get a build error.

You can optionally set the following environment variables for the build:

* USE_AUTOMATION_PERMISSIONS - build packages to have some directories not owned
by root
* AUTOMATION_USER - the user that will be running the scripts (and generating
file output)
* AUTOMATION_GROUP - the group

You can combine these things in a script (where makefile_path is set
appropriately):

```
#!/bin/bash

makefile_path="$HOME/src/git/github_theias/ias_nagios_infoblox_scripts/Makefile"
export AUTOMATION_USER=root
export AUTOMATION_GROUP=root

fakeroot \
make -f "$makefile_path" \
package-rpm
```

## Requirements

### All Systems

* fakeroot

### Debian

* build-essential

### RHEL based systems

* rpm-build

## Export a specific tag (or just the source directory)

## Supported Systems

### Debian packages

<pre>
fakeroot make package-deb
</pre>

### RHEL Based Systems

<pre>
fakeroot make package-rpm
</pre>
