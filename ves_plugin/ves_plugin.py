
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
        self.event_type = "LossOfSignal" #should change this to something else
        self.domain = ""
        self.event_id = ""
        self.source_id = "23380d70-2c71-4e35-99e2-f43f97e4ec65"
        self.source_name = "cscf0001vm001abc001"
        self.functional_role = "SGW"
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
        self.mean_request_latency = 1
        self.measurement_fields_version = 1.1
        self.measurement_interval = 1
        self.memory_configured = 2
        self.memory_used = 3
        self.number_of_media_ports_in_use = 4
        self.request_rate = 5
        self.vnfc_scaling_metric = 6
        self.v_nic_usage_array = []

    def add_measurement_group(self, group):
        self.additional_measurements.append(group.get_obj())

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
        return "measurementsForVfScaling"

class Fault(Event):
    """Fault datatype"""

    def __init__(self, event_id):
        """Construct the header"""
        super(Fault, self).__init__()
        # common attributes
        self.domain = "fault"
        self.event_id = event_id
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
            'cpu' : [], 'virt' : [], 'disk' : [], 'interface' : [], 'memory' : []
        }
        self.__ves_timer = None
        self.__event_timer_interval = 20.0
        self.__lock = Lock()
        self.__username = ''
        self.__password = ''
        self.__port = 30000
        self.__path = ''
        self.__event_id = 0
        self.__domain = '127.0.0.1'

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
        server_url = "http://{}:{}/{}eventListener/v1".format(self.__domain, self.__port,
            '{}/'.format(self.__path) if (len(self.__path) > 0) else '')
        collectd.debug('Vendor Event Listener is at: {}'.format(server_url))
        credentials = base64.b64encode('{}:{}'.format(self.__username, self.__password))
        collectd.debug('Authentication credentials are: {}'.format(credentials))
        try:
            request = urllib2.Request(server_url)
            request.add_header('Authorization', 'Basic {}'.format(credentials))
            request.add_header('Content-Type', 'application/json')
            collectd.debug("Sending {} to {}".format(event.get_json(), server_url))
            vel = urllib2.urlopen(request, event.get_json(), timeout=1)
        except urllib2.HTTPError as e:
            colectd.error('Vendor Event Listener exception: {} [{}]'.format(vel.read(), vel.getcode()))
        except urllib2.URLError as e:
            collectd.error('Vendor Event Listener is is not reachable: {}'.format(e))

    def event_timer(self):
        """Event timer thread"""
        self.lock()
        try:
            # make sure that 'virt' plugin cache is up-to-date
            for val in self.__plugin_data_cache['virt']:
                #collectd.info(">>> plugin={}, plugin_instance={}, type_instance={}, type={}, time={}, values={}".
                #format('virt', val['plugin_instance'], val['type_instance'], val['type'], val['time'],
                #val['values']))
                if val['updated'] == False:
                    # one of the cache value is not up-to-date, break
                    collectd.warning("virt collectD cache values are not up-to-date")
                    break
            # if values are up-to-date, create an event message
            measurement = MeasurementForVfScaling(self.get_event_id())
            virt_vcpu_total = self.cache_get_value('virt', 'virt_cpu_total')
            measurement.aggregate_cpu_usage = virt_vcpu_total if virt_vcpu_total else 0.0

            # add host/guest values as additional measurements
            for plugin_name in self.__plugin_data_cache.keys():
                if plugin_name == 'virt':
                    # skip host-only values
                    continue;
                for val in self.__plugin_data_cache[plugin_name]:
                    mgroup_name = '{}-{}'.format(plugin_name, val['plugin_instance'])
                    mgroup = MeasurementGroup(mgroup_name)
                    mgroup_value = '{}-{}'.format(val['type'], val['type_instance'])
                    mgroup.add_measurement(mgroup_value, str(val['values']))
                    measurement.add_measurement_group(mgroup);
                    val['updated'] = False
            # send event to the VES
            self.event_send(measurement)
        finally:
            self.unlock()

    def config(self, config):
        """Collectd config callback"""
        # TODO Implement python read configuration
        pass

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
        plugin_vl = self.__plugin_data_cache[vl.plugin]
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
            self.__plugin_data_cache[vl.plugin].append(value)

    def cache_get_value(self, plugin_name, type_name):
        """Get cache value by given criteria"""
        if plugin_name in self.__plugin_data_cache:
            for val in self.__plugin_data_cache[plugin_name]:
                collectd.info("plugin={}, type={}".format(plugin_name, val['type']))
                if type_name == val['type']:
                    val['updated'] = False
                    return self.collectd_to_ves_type(val['type'], val['values'])
        return None

    def collectd_to_ves_type(self, type_name, value):
        """Convert collectD type to VES"""
        collectd_convert_type_map = {
            'virt_cpu_total' : lambda x : int(x[0])
        }
        if type_name in collectd_convert_type_map.keys():
            return collectd_convert_type_map[type_name](value)
        return value

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
