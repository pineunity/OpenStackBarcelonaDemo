# OpenStackBarcelonaDemo
This repository contains a python based write plugin for VES.

The plugin currently supports pushing platform relavent metrics through the additional measurements field for VES.

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

**GuestRunning** *true|false*
+ This option is used if the collectd is running on a guest machine, e.g this option should be set
to `true` in this case. Defaults to `false`.


##Other collectd.conf configurations

Please ensure that FQDNLookup is set to false
```
FQDNLookup   false
```

Please ensure that the virt plugin is enabled and configured as follows. This configuration
is is required only on a host side ('GuestRunning' = false).
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
Please ensure that the aggregation plugin is enabled and configured as follows
```
LoadPlugin aggregation

<Plugin aggregation>
        <Aggregation>
                Plugin "cpu"
                Type "percent"
                GroupBy "Host"
                GroupBy "TypeInstance"
                SetPlugin "cpu-aggregation"
                CalculateAverage true
        </Aggregation>
</Plugin>
```

If plugin is running on a guest side, it is important to enable uuid plugin too. In this case
the hostname in event message will be represented as UUID instead of system host name.
```
LoadPlugin uuid
```
If custom UUID needs to be provided, the following configuration is required in collectd.conf
file:
```
<Plugin uuid>
        UUIDFile "/etc/uuid"
</Plugin>
```
Where "/etc/uuid" is a file containing custom UUID.

Please also ensure that the following plugins are enabled:
```
LoadPlugin disk
LoadPlugin interface
LoadPlugin memory
```

##VES plugin notification example

A good example of collectD notification is monitoring of CPU load on a host or guest using
'threshold' plugin. The following configuration will setup VES plugin to send 'Fault'
event every time a CPU idle value is out of range (e.g.: WARNING: CPU-IDLE < 50%, CRITICAL:
CPU-IDLE < 30%) and send 'Fault' NORMAL event if CPU idle value is back to normal.
```
LoadPlugin threshold

<Plugin "threshold">
    <Plugin "cpu-aggregation">
        <Type "percent">
            WarningMin    50.0
            WarningMax   100.0
            FailureMin    30.0
            FailureMax   100.0
            Instance "idle"
            Hits 1
        </Type>
    </Plugin>
</Plugin>
```
More detailed information on how to configure collectD thresholds(memory, cpu etc.) can be found here at
[collectd-threshold.5](https://collectd.org/documentation/manpages/collectd-threshold.5.shtml)
