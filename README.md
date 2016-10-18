# OpenStackBarcelonaDemo
This repository contains a python based write plugin for VES.

The plugin currently supports pushing platform relavent metrics through the additional measurements field for VES.

TODO:
* Remove hard coded values, these will become configuration options for the plugin.
* Push virt plugin values in the main fields.

**Please note**: Hardcoded configuration values will be modified so that they are configurable through the configuration file.

##Installation Instructions:
1. Clone this repo
2. Install collectd
```
   $ sudo apt-get install collectd
```
3. Modify the collectd configuration script: `/etc/collectd/collectd.conf`
```

    <LoadPlugin python>
      Globals true
    </LoadPlugin>

    <Plugin python>
      ModulePath "/path/to/your/python/modules"
      LogTraces true
      Interactive false
      Import "ves_plugin"
    <Module ves_plugin>
    </Module>
    </Plugin>
```
where "/path/to/your/python/modules" is the path to where you cloned this repo

##Other collectd.conf configurations

Please ensure that FQDNLookup is set to false
```
FQDNLookup   false
```

Please ensure that the virt plugin is enabled and configured as follows
```
LoadPlugin virt

<Plugin virt>
        Connection "qemu:///system"
        RefreshInterval 60
        HostnameFormat uuid
</Plugin>
```

Please ensure that the cpu plugin is enabled and configured as follows
```
LoadPlugin cpu

<Plugin cpu>
        ReportByCpu false
        ValuesPercentage true
</Plugin>
```
Please also ensure that the following plugins are enabled:
```
LoadPlugin disk
LoadPlugin interface
LoadPlugin memory
```
