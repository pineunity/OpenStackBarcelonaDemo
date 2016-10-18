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
    LoadPlugin python
    # ...
    <LoadPlugin python>
      Globals true
    </LoadPlugin>
    # ...
    <Plugin python>
      ModulePath "/path/to/your/python/modules"
      LogTraces true
      Interactive false
      Import "ves_plugin"
    <Module ves_plugin>
    </Module>
    </Plugin>
```


