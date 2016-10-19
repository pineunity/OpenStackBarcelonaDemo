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
    # VES plugin configuration (see next section below)
    </Module>
    </Plugin>
```
where "/path/to/your/python/modules" is the path to where you cloned this repo

## VES python plugin configuration description:

> **Note** Details of the Vendor Event Listener REST service

```
REST resources are defined with respect to a ServerRoot:
ServerRoot = https://{Domain}:{Port}/{optionalRoutingPath}

REST resources are of the form:

{ServerRoot}/eventListener/v{apiVersion}`
{ServerRoot}/eventListener/v{apiVersion}/{topicName}`
{ServerRoot}/eventListener/v{apiVersion}/eventBatch`
```

**Domain** *"host"*
+ VES domain name. It can be IP addresses or hostname of VES collector (default: `127.0.0.1`)

**Port** *port*
+ VES port (default: `30000`)

**Path** *"path"*
+ Used as the "optionalRoutingPath" element in the REST path (default: `empty`)

**Topic** *"path"*
+ Used as the "topicName" element in the REST  path (default: `empty`)

**UseHttps** *true|false*
+ Allow plugin to use HTTPS instead of HTTP (default: `false`)

**Username** *"username"*
+ VES collector user name (default: `empty`)

**Password** *"passwd"*
+ VES collector password (default: `empty`)

**FunctionalRole** *"role"*
+ Used as the 'functionalRole' field of 'commonEventHeader' event (default: `Collectd VES Agent`)


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
