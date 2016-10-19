
# Copyright 2016 Intel Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import collectd
import json
import sys
import base64
import logging
import urllib2
from threading import Timer
from threading import Lock

class Event(object):
    """Event header"""

    def __init__(self):
        """Construct the common header"""
        self.version = 1.1
        self.event_type = "Info" # use "Info" unless a notification is generated
        self.domain = ""
        self.event_id = ""
        self.source_id = "23380d70-2c71-4e35-99e2-f43f97e4ec65"
        self.source_name = "cscf0001vm001abc001"
        self.functional_role = ""
        self.reporting_entity_id = ""
        self.reporting_entity_name = "cscf0001vm001oam001" # to be changed to hostname_plugin_plugin-instance name
        self.priority = "Normal" # will be derived from event if there is one
        self.start_epoch_microsec = 1413378172000000 # will be the interval value
        self.last_epoch_micro_sec = 1413378172000000 # will be the interval value
        self.sequence = 0

    def get_json(self):
        """Get the object of the datatype"""
        obj = {}
        obj['version'] = self.version
        obj['eventType'] = self.event_type
        obj['domain'] = self.domain
        obj['eventId'] = self.event_id
        obj['sourceId'] = self.source_id
        obj['sourceName'] = self.source_name
        obj['functionalRole'] = self.functional_role
        obj['reportingEntityId'] = self.reporting_entity_id
        obj['reportingEntityName'] = self.reporting_entity_name
        obj['priority'] = self.priority
        obj['startEpochMicrosec'] = self.start_epoch_microsec
        obj['lastEpochMicrosec'] = self.last_epoch_micro_sec
        obj['sequence'] = self.sequence
        return json.dumps({
            'event' : {
                'commonEventHeader' : obj,
                self.get_name() : self.get_obj()
            }
        })

    def get_name():
        assert False, 'abstract method get_name() is not implemented'

    def get_obj():
        assert False, 'abstract method get_obj() is not implemented'

class MeasurementGroup(object):
    """MeasurementGroup datatype"""

    def __init__(self, name):
        self.name = name
        self.measurement = []
        pass

    def add_measurement(self, name, value):
        self.measurement.append({
            'name' : name,
            'value' : value
        })

    def get_obj(self):
        return {
            'name' : self.name,
            'measurements' : self.measurement
        }

class MeasurementsForVfScaling(Event):
    """MeasurementsForVfScaling datatype"""

    def __init__(self, event_id):
        """Construct the header"""
        super(MeasurementsForVfScaling, self).__init__()
        # common attributes
        self.domain = "measurementsForVfScaling"
        self.event_id = event_id
        # measurement attributes
        self.additional_measurements = []
        self.aggregate_cpu_usage = 0
        self.codec_usage_array = []
        self.concurrent_sessions = 0
        self.configured_entities = 0
        self.cpu_usage_array = []
        self.errors = []
        self.feature_usage_array = []
        self.filesystem_usage_array = []
        self.latency_distribution = []
        self.mean_request_latency = 0
        self.measurement_fields_version = 1.1
        self.measurement_interval = 0
        self.memory_configured = 0
        self.memory_used = 0
        self.number_of_media_ports_in_use = 0
        self.request_rate = 0
        self.vnfc_scaling_metric = 0
        self.v_nic_usage_array = []

    def add_measurement_group(self, group):
        self.additional_measurements.append(group.get_obj())

    def add_cpu_usage(self, cpu_identifier, usage):
        self.cpu_usage_array.append({
            'cpuIdentifier' : cpu_identifier,
            'percentUsage' : usage
        })

    def add_v_nic_usage(self, if_name, if_pkts, if_bytes):
        self.v_nic_usage_array.append({
            'broadcastPacketsIn' : 0.0,
            'broadcastPacketsOut' : 0.0,
            'multicastPacketsIn' : 0.0,
            'multicastPacketsOut' : 0.0,
            'unicastPacketsIn' : 0.0,
            'unicastPacketsOut' : 0.0,
            'vNicIdentifier' : if_name,
            'packetsIn' : if_pkts[0],
            'packetsOut' : if_pkts[1],
            'bytesIn' : if_bytes[0],
            'bytesOut' : if_bytes[1]
        })

    def get_obj(self):
        """Get the object of the datatype"""
        obj = {}
        obj['additionalMeasurements'] = self.additional_measurements
        obj['aggregateCpuUsage'] = self.aggregate_cpu_usage
        obj['codecUsageArray'] = self.codec_usage_array
        obj['concurrentSessions'] = self.concurrent_sessions
        obj['configuredEntities'] = self.configured_entities
        obj['cpuUsageArray'] = self.cpu_usage_array
        obj['errors'] = self.errors
        obj['featureUsageArray'] = self.feature_usage_array
        obj['filesystemUsageArray'] = self.filesystem_usage_array
        obj['latencyDistribution'] = self.latency_distribution
        obj['meanRequestLatency'] = self.mean_request_latency
        obj['measurementFieldsVersion'] = self.measurement_fields_version
        obj['measurementInterval'] = self.measurement_interval
        obj['memoryConfigured'] = self.memory_configured
        obj['memoryUsed'] = self.memory_used
        obj['numberOfMediaPortsInUse'] = self.number_of_media_ports_in_use
        obj['requestRate'] = self.request_rate
        obj['vnfcScalingMetric'] = self.vnfc_scaling_metric
        obj['vNicUsageArray'] = self.v_nic_usage_array
        return obj

    def get_name(self):
        """Name of datatype"""
        return "measurementsForVfScalingFields"

class Fault(Event):
    """Fault datatype"""

    def __init__(self, event_id):
        """Construct the header"""
        super(Fault, self).__init__()
        # common attributes
        self.domain = "fault"
        self.event_id = event_id
        self.event_type = "Fault"
        # fault attributes
        self.fault_fields_version = 1.1
        self.event_severity = 'NORMAL'
        self.event_source_type = 'port(5)'
        self.alarm_condition = ''
        self.specific_problem = 'LinkDown'
        self.vf_status = 'Active'
        self.alarm_interface_a = ''
        self.alarm_additional_information = []

    def get_name(self):
        """Name of datatype"""
        return 'faultFields'

    def get_obj(self):
        """Get the object of the datatype"""
        obj = {}
        obj['faultFieldsVersion'] = self.fault_fields_version
        obj['eventSeverity'] = self.event_severity
        obj['eventSourceType'] = self.event_source_type
        obj['alarmCondition'] = self.alarm_condition
        obj['specificProblem'] = self.specific_problem
        obj['vfStatus'] = self.vf_status
        obj['alarmInterfaceA'] = self.alarm_interface_a
        obj['alarmAdditionalInformation'] = self.alarm_additional_information
        return obj

class VESPlugin(object):
    """VES plugin with collectd callbacks"""

    def __init__(self):
        """Plugin initialization"""
        self.__plugin_data_cache = {
            'cpu' : {'interval' : 0.0, 'vls' : []},
            'virt' : {'interval' : 0.0, 'vls' : []},
            'disk' : {'interval' : 0.0, 'vls' : []},
            'interface' : {'interval' : 0.0, 'vls' : []},
            'memory' : {'interval' : 0.0, 'vls' : []}
        }
        self.__plugin_config = {
            'Domain' : '127.0.0.1',
            'Port' : 30000.0,
            'Path' : '',
            'Username' : '',
            'Password' : '',
            'Topic' : '',
            'UseHttps' : False,
            'SendEventInterval' : 20.0,
            'FunctionalRole' : 'Collectd VES Agent'
        }
        self.__ves_timer = None
        self.__event_timer_interval = 20.0
        self.__lock = Lock()
        self.__event_id = 0

    def get_event_id(self):
        """get event id"""
        self.__event_id += 1
        return str(self.__event_id)

    def lock(self):
        """Lock the plugin"""
        self.__lock.acquire()

    def unlock(self):
        """Unlock the plugin"""
        self.__lock.release()

    def start_timer(self):
        """Start event timer"""
        self.__ves_timer = Timer(self.__event_timer_interval, self.__on_time)
        self.__ves_timer.start()

    def stop_timer(self):
        """Stop event timer"""
        self.__ves_timer.cancel()

    def __on_time(self):
        """Timer thread"""
        self.start_timer()
        self.event_timer()

    def event_send(self, event):
        """Send event to VES"""
        server_url = "http{}://{}:{}/{}eventListener/v1{}".format(
            's' if self.__plugin_config['UseHttps'] else '', self.__plugin_config['Domain'],
            int(self.__plugin_config['Port']), '{}/'.format(
            '/{}'.format(self.__plugin_config['Path'])) if (len(self.__plugin_config['Path']) > 0) else '',
            self.__plugin_config['Topic'])
        collectd.info('Vendor Event Listener is at: {}'.format(server_url))
        credentials = base64.b64encode('{}:{}'.format(
            self.__plugin_config['Username'], self.__plugin_config['Password']))
        collectd.info('Authentication credentials are: {}'.format(credentials))
        try:
            request = urllib2.Request(server_url)
            request.add_header('Authorization', 'Basic {}'.format(credentials))
            request.add_header('Content-Type', 'application/json')
            collectd.debug("Sending {} to {}".format(event.get_json(), server_url))
            vel = urllib2.urlopen(request, event.get_json(), timeout=1)
        except urllib2.HTTPError as e:
            collectd.error('Vendor Event Listener exception: {}'.format(e))
        except urllib2.URLError as e:
            collectd.error('Vendor Event Listener is is not reachable: {}'.format(e))

    def bytes_to_gb(self, bytes):
        """Convert bytes to GB"""
        return (bytes / 1073741824.0)

    def event_timer(self):
        """Event timer thread"""
        self.lock()
        try:
            # get list of all VMs
            virt_vcpu_total = self.cache_get_value(plugin_name='virt', type_name='virt_cpu_total',
                                                   mark_as_read=False)
            vm_names = [x['plugin_instance'] for x in virt_vcpu_total]
            for vm_name in vm_names:
                # make sure that 'virt' plugin cache is up-to-date
                vm_values = self.cache_get_value(plugin_name='virt', plugin_instance=vm_name,
                                                 mark_as_read=False)
                us_up_to_date = True
                for vm_value in vm_values:
                    if vm_value['updated'] == False:
                        us_up_to_date = False
                        break
                if not us_up_to_date:
                        # one of the cache value is not up-to-date, break
                        collectd.warning("virt collectD cache values are not up-to-date for {}".format(vm_name))
                        continue
                # if values are up-to-date, create an event message
                measurement = MeasurementsForVfScaling(self.get_event_id())
                measurement.functional_role = self.__plugin_config['FunctionalRole']
                # virt_cpu_total
                virt_vcpu_total = self.cache_get_value(plugin_instance=vm_name,
                                                       plugin_name='virt', type_name='virt_cpu_total')
                if len(virt_vcpu_total) > 0:
                    measurement.aggregate_cpu_usage = virt_vcpu_total[0]['values'][0]
                # virt_vcp
                virt_vcpus = self.cache_get_value(plugin_instance=vm_name,
                                                  plugin_name='virt', type_name='virt_vcpu')
                if len(virt_vcpus) > 0:
                    for virt_vcpu in virt_vcpus:
                        measurement.add_cpu_usage(virt_vcpu['type_instance'], virt_vcpu['values'][0])
                # plugin interval
                measurement.measurement_interval = self.__plugin_data_cache['virt']['interval']
                # memory-total
                memory_total = self.cache_get_value(plugin_instance=vm_name, plugin_name='virt',
                                                    type_name='memory', type_instance='total')
                if len(memory_total) > 0:
                    measurement.memory_configured = self.bytes_to_gb(memory_total[0]['values'][0])
                # memory-rss
                memory_rss = self.cache_get_value(plugin_instance=vm_name, plugin_name='virt',
                                                  type_name='memory', type_instance='rss')
                if len(memory_rss) > 0:
                    measurement.memory_used = self.bytes_to_gb(memory_rss[0]['values'][0])
                # if_packets
                ifinfo = {}
                if_stats = self.cache_get_value(plugin_instance=vm_name,
                                                plugin_name='virt', type_name='if_packets')
                if len(if_stats) > 0:
                    for if_stat in if_stats:
                        ifinfo[if_stat['type_instance']] = {
                            'pkts' : (if_stat['values'][0], if_stat['values'][1])
                        }
                # go through all interfaces and get if_octets
                for if_name in ifinfo.keys():
                    if_stats = self.cache_get_value(plugin_instance=vm_name, plugin_name='virt',
                                                    type_name='if_octets', type_instance=if_name)
                    if len(if_stats) > 0:
                        ifinfo[if_name]['bytes'] = (if_stats[0]['values'][0], if_stats[0]['values'][1])
                # fill vNicUsageArray filed in the event
                for if_name in ifinfo.keys():
                    measurement.add_v_nic_usage(if_name, ifinfo[if_name]['pkts'], ifinfo[if_name]['bytes'])

                # add host/guest values as additional measurements
                for plugin_name in self.__plugin_data_cache.keys():
                    if plugin_name == 'virt':
                        # skip host-only values
                        continue;
                    for val in self.__plugin_data_cache[plugin_name]['vls']:
                        mgroup_name = '{}{}'.format(plugin_name, '-{}'.format(
                            val['plugin_instance']) if len(val['plugin_instance']) else '')
                        mgroup = MeasurementGroup(mgroup_name)
                        measurements = self.collectd_type_to_measurements(val)
                        for m in measurements:
                            mgroup.add_measurement(m[0], str(m[1]))
                        measurement.add_measurement_group(mgroup);
                        val['updated'] = False
                # send event to the VES
                self.event_send(measurement)
        finally:
            self.unlock()

    def collectd_type_to_measurements(self, vl):
        collectd_type_map = {
            'if_packets' : lambda value : [('if_packets-rx', value[0]), ('if_packets-tx', value[1])],
            'if_octets' : lambda value : [('if_octets-rx', value[0]), ('if_octets-tx', value[1])],
            'if_errors' : lambda value : [('if_errors-rx', value[0]), ('if_errors-tx', value[1])],
            'disk_octets' : lambda value : [('disk_octets-read', value[0]), ('disk_octets-write', value[1])],
            'disk_ops' : lambda value : [('disk_ops-read', value[0]), ('disk_ops-write', value[1])],
            'disk_merged' : lambda value : [('disk_merged-read', value[0]), ('disk_merged-write', value[1])],
            'disk_time' : lambda value : [('disk_time-read', value[0]), ('disk_time-write', value[1])],
            'disk_io_time' : lambda value : [('disk_io_time-io_time', value[0]), ('disk_io_time-weighted_io_time', value[1])],
            'pending_operations' : lambda value : [('pending_operations', value[0])]
        }
        if vl['type'] in collectd_type_map.keys():
            # convert collectD type to VES type
            return collectd_type_map[vl['type']](vl['values'])
        # do general convert
        return [('{}-{}'.format(vl['type'], vl['type_instance']), vl['values'][0])]

    def config(self, config):
        """Collectd config callback"""
        for child in config.children:
            # check the config entry name
            if child.key not in self.__plugin_config:
                collectd.error("Key '{}' name is invalid".format(child.key))
                raise RuntimeError('Configuration key name error')
            # check the config entry value type
            if len(child.values) == 0 or type(child.values[0]) != type(self.__plugin_config[child.key]):
                collectd.error("Key '{}' value type should be {}".format(
                               child.key, str(type(self.__plugin_config[child.key]))))
                raise RuntimeError('Configuration key value error')
            # store the value in configuration
            self.__plugin_config[child.key] = child.values[0]

    def init(self):
        """Collectd init callback"""
        # start the VES timer
        self.start_timer()

    ##
    # Please note, the cache should be locked before using this function
    #
    def update_cache_value(self, vl):
        """Update value internal collectD cache values or create new one"""
        found = False
        plugin_vl = self.__plugin_data_cache[vl.plugin]['vls']
        for index in xrange(len(plugin_vl)):
            # record found, so just update time the values
            if (plugin_vl[index]['plugin_instance'] ==
                vl.plugin_instance) and (plugin_vl[index]['type_instance'] ==
                    vl.type_instance) and (plugin_vl[index]['type'] == vl.type):
                plugin_vl[index]['time'] = vl.time
                plugin_vl[index]['values'] = vl.values
                plugin_vl[index]['updated'] = True
                found = True
                break
        if not found:
            value = {}
            # create new cache record
            value['plugin_instance'] = vl.plugin_instance
            value['type_instance'] = vl.type_instance
            value['values'] = vl.values
            value['type'] = vl.type
            value['time'] = vl.time
            value['updated'] = True
            self.__plugin_data_cache[vl.plugin]['vls'].append(value)
            # update plugin interval based on one received in the value
            self.__plugin_data_cache[vl.plugin]['interval'] = vl.interval

    def cache_get_value(self, plugin_name=None, plugin_instance=None,
                        type_name=None, type_instance=None, type_names=None, mark_as_read=True):
        """Get cache value by given criteria"""
        ret_list = []
        if plugin_name in self.__plugin_data_cache:
            for val in self.__plugin_data_cache[plugin_name]['vls']:
                #collectd.info("plugin={}, type={}, type_instance={}".format(
                #    plugin_name, val['type'], val['type_instance']))
                if (type_name == None or type_name == val['type']) and (plugin_instance == None
                    or plugin_instance == val['plugin_instance']) and (type_instance == None
                    or type_instance == val['type_instance']) and (type_names == None
                    or val['type'] in type_names):
                    if mark_as_read:
                        val['updated'] = False
                    ret_list.append(val)
        return ret_list

    def write(self, vl, data=None):
        """Collectd write callback"""
        self.lock()
        try:
            # Example of collectD Value format
            # collectd.Values(type='cpu',type_instance='interrupt',
            # plugin='cpu',plugin_instance='25',host='localhost',
            # time=1476694097.022873,interval=10.0,values=[0])
            if vl.plugin in self.__plugin_data_cache.keys():
                # update the cache values
                self.update_cache_value(vl)
        finally:
            self.unlock()

    def notify(self, n):
        """Collectd notification callback"""
        # type='gauge',type_instance='link_status',plugin='ovs_events',plugin_instance='br0',
        # host='silv-vmytnyk-nos.ir.intel.com',time=1476441572.7450583,severity=4,
        # message='link state of "br0" interface has been changed to "UP"')
        collectd_event_severity_map = {
            collectd.NOTIF_FAILURE : 'CRITICAL',
            collectd.NOTIF_WARNING : 'WARNING',
            collectd.NOTIF_OKAY : 'NORMAL'
        }
        fault = Fault(self.get_event_id())
        fault.functional_role = self.__plugin_config['FunctionalRole']
        fault.event_severity = collectd_event_severity_map[n.severity]
        fault.specific_problem = '{}-{}'.format(n.plugin_instance, n.type_instance)
        fault.alarm_condition = n.message
        self.event_send(fault)

    def shutdown(self):
        """Collectd shutdown callback"""
        # stop the timer
        self.stop_timer()

# The collectd plugin instance
plugin_instance = VESPlugin()

# Register plugin callbacks
collectd.register_config(plugin_instance.config)
collectd.register_init(plugin_instance.init)
collectd.register_write(plugin_instance.write)
collectd.register_notification(plugin_instance.notify)
collectd.register_shutdown(plugin_instance.shutdown)
