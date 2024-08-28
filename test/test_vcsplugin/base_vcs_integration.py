##############################################################################
# COPYRIGHT Ericsson AB 2013
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

from vcsplugin.vcs_plugin import VcsPlugin
from package_plugin.package_plugin import PackagePlugin
from cba_extension.cba_extension import CBAExtension
from vcs_extension.vcs_extension import VcsExtension
from package_extension.package_extension import PackageExtension
from volmgr_extension.volmgr_extension import VolMgrExtension
from bootmgr_extension.bootmgr_extension import BootManagerExtension

from litp.extensions.core_extension import CoreExtension
from network_extension.network_extension import NetworkExtension
from litp.core.model_manager import ModelManager
from litp.core.puppet_manager import PuppetManager
from litp.core.execution_manager import ExecutionManager

from litp.core.plugin_manager import PluginManager
from litp.core.validators import ValidationError
from litp.core.plugin_context_api import PluginApiContext
from litp.core.callback_api import CallbackApi

import unittest
import mock


class VCSIntegrationBase(unittest.TestCase):

    def _strip_kwargs(self, kwargs):
        del kwargs['callback_class']
        del kwargs['callback_func']
        return kwargs

    def _print_task_descriptions(self, tasks):
        for task in tasks:
            if hasattr(task, "description"):
                print task.description
            if hasattr(task, "task_list"):
                self._print_task_descriptions(task.task_list)

    @mock.patch('litp.core.base_plugin_api._SecurityApi')
    def setUp(self, _SecurityApi_mock):
        self.node1 = self.node2 = None
        self.model = ModelManager()
        self.plugin_manager = PluginManager(self.model)

        core_ext = CoreExtension()
        network_ext = NetworkExtension()
        cba_ext = CBAExtension()
        vcs_ext = VcsExtension()
        pkg_ext = PackageExtension()
        vol_ext = VolMgrExtension()
        bootmgr_ext = BootManagerExtension()

        for ext in [core_ext, network_ext, cba_ext, pkg_ext, vcs_ext,
                    vol_ext, bootmgr_ext]:
            self.plugin_manager.add_property_types(ext.define_property_types())
            self.plugin_manager.add_item_types(ext.define_item_types())
            if ext == core_ext:
                self.plugin_manager.add_default_model()

        self.plugin = VcsPlugin()
        for plugin in [VcsPlugin, PackagePlugin]:
            self.plugin_manager.add_plugin(plugin.__name__,
                                           "{0}.{1}".format(plugin.__module__,
                                                            plugin.__name__),
                                           "1.0.0", plugin())
        self.context_api = PluginApiContext(self.model)

        self.puppet_manager = PuppetManager(self.model, '/tmp')
        self.execution_manager = ExecutionManager(self.model,
                                                  self.puppet_manager,
                                                  self.plugin_manager)
        self.execution_manager.is_plan_running = lambda: True
        self.callback_api = CallbackApi(self.execution_manager)

    def _add_item_to_model(self, *args, **kwargs):
        result = self.model.create_item(*args, **kwargs)
        self._assess_result(result)
        return result

    def _remove_item_from_model(self, vpath):
        result = self.model.remove_item(vpath)
        self._assess_result(result)
        return result

    def _update_item_in_model(self, *args, **kwargs):
        result = self.model.update_item(*args, **kwargs)
        self._assess_result(result)
        return result

    def _add_inherit_to_model(self, source_item_path, item_path, **properties):
        result = self.model.create_inherited(source_item_path, item_path,
                                             **properties)
        self._assess_result(result)
        return result

    def _assess_result(self, result):
        try:
            checks = [type(result) is list,
                      len(result),
                      type(result[0]) is ValidationError]
        except TypeError:  # result is not list
            pass
        except IndexError:  # result is empty list
            pass
        else:
            if all(checks):
                raise RuntimeError(repr(result[0]))

    @staticmethod
    def string_and_sort(errors):
        return sorted([str(error) for error in errors])

    def add_cluster(self, num_of_nodes=2, cluster_type="vcs-cluster",
                    cluster_id='1234', fencing_num=0, vcs_cluster_type="sfha",
                    cluster_name="cluster1", ha_manager="vcs",
                    vcs_seed_threshold=None, app_agent_num_threads=None,
                    is_rack_cluster=False):
        cluster_str = "/deployments/test/clusters/%s" % cluster_name
        if cluster_type == "vcs-cluster":
            cluster_properties = {
                'ha_manager': ha_manager,
                'cluster_type': vcs_cluster_type,
                'llt_nets': "heartbeat1,heartbeat2",
                'low_prio_net': "mgmt"}

            if cluster_id:
                cluster_properties['cluster_id'] = cluster_id

            if vcs_seed_threshold:
                cluster_properties['vcs_seed_threshold'] = vcs_seed_threshold

            if app_agent_num_threads:
                cluster_properties['app_agent_num_threads'] = app_agent_num_threads

            self._add_item_to_model("vcs-cluster",
                                    cluster_str,
                                    **cluster_properties)

            for i in range(0, fencing_num):
                self._add_item_to_model("disk",
                                cluster_str + "/fencing_disks/fd%d" % i,
                                name='fencing_disk_{0}'.format(i),
                                uuid='10%d' % i,
                                size='1G')
        elif cluster_type == "cmw-cluster":
            self._add_item_to_model(
                "cmw-cluster",
                cluster_str,
                ha_manager="cmw",
                cluster_id="1234")
        else:
            self._add_item_to_model(
                "cluster",
                cluster_str)

        # if non vcs or cmw, no heartbeats
        if cluster_type in ["vcs-cluster", "cmw-cluster"]:
            # create nodes
            for i in range(1, num_of_nodes + 1):
                self.add_node(cluster_str, i, is_rack_node=is_rack_cluster)

    def add_node(self, cluster_vpath, node_id, is_rack_node=False):
        # Create node systems
        system_vpath = '/infrastructure/systems/system_%d' % node_id
        if not self.model.get_item(system_vpath):
            self._add_item_to_model('system', system_vpath,
                                    system_name='MN%d' % node_id)

        # Create node
        self._add_item_to_model(
            "node",
            cluster_vpath + "/nodes/node%d" % node_id,
            hostname="mn%d" % node_id,
            node_id="%d" % node_id)
        self._add_inherit_to_model(
            "/infrastructure/systems/system_%d" % node_id,
            cluster_vpath + "/nodes/node%d/system" % node_id)
        self._add_inherit_to_model(
            "/infrastructure/networking/routes/def_route",
            cluster_vpath + "/nodes/node%d/routes/r_0" % node_id)
        self._add_inherit_to_model(
            '/software/profiles/rhel_6_4',
            cluster_vpath + "/nodes/node%d/os" % node_id)
        self._add_inherit_to_model(
            '/infrastructure/storage/storage_profiles/profile_1',
            cluster_vpath + "/nodes/node%d/storage_profile" % node_id)
        if not is_rack_node:
            self._add_item_to_model(
                'eth',
                cluster_vpath + "/nodes/node%d/network_interfaces/if0" % node_id,
                macaddress="08:00:27:5B:C1:3%d" % node_id,
                network_name="mgmt",
                device_name="eth0",
                ipaddress="10.10.10.%d" % node_id)
            self._add_item_to_model(
                'eth',
                cluster_vpath + "/nodes/node%d/network_interfaces/if1" % node_id,
                macaddress="08:00:27:5B:C1:3%d" % node_id,
                network_name="heartbeat1",
                device_name="eth1")
            self._add_item_to_model(
                'eth',
                cluster_vpath + "/nodes/node%d/network_interfaces/if2" % node_id,
                macaddress="08:00:27:5B:C1:3%d" % node_id,
                network_name="heartbeat2",
                device_name="eth2")
        else:
            self._add_item_to_model(
                'bridge',
                cluster_vpath + "/nodes/node%d/network_interfaces/br0" % node_id,
                device_name="br0",
                hash_max="512",
                ipaddress="10.10.10.%d" % node_id,
                hash_elasticity="4",
                forwarding_delay="4",
                multicast_router="1",
                stp="false",
                multicast_snooping="1",
                network_name="mgmt",
                multicast_querier="0")

            self._add_item_to_model(
                'bond',
                cluster_vpath + "/nodes/node%d/network_interfaces/bond0" % node_id,
                device_name="bond0",
                bridge="br0",
                mode="4",
                xmit_hash_policy="layer3+4",
                miimon="100")

            self._add_item_to_model(
                'eth',
                cluster_vpath + "/nodes/node%d/network_interfaces/if0" % node_id,
                macaddress="08:00:27:5B:C1:3%d" % node_id,
                device_name="eth0",
                master="bond0")

            self._add_item_to_model(
                'vlan',
                cluster_vpath + "/nodes/node%d/network_interfaces/vlan_hb1" % node_id,
                network_name="heartbeat1",
                device_name="bond0.91")

            self._add_item_to_model(
                'vlan',
                cluster_vpath + "/nodes/node%d/network_interfaces/vlan_hb2" % node_id,
                network_name="heartbeat2",
                device_name="bond0.17")

    def setup_model(self, num_of_nodes=2, cluster_type="vcs-cluster",
                    cluster_id='1234', fencing_num=0, vcs_cluster_type="sfha",
                    num_of_clusters=1, ha_manager="vcs",
                    vcs_seed_threshold=None, app_agent_num_threads=None,
                    is_rack_deployment=False):
        self._add_item_to_model(
            'network',
            '/infrastructure/networking/networks/mgmt',
            name='mgmt',
            subnet='10.10.10.0/24',
            litp_management='true')
        self._add_item_to_model(
            'os-profile',
            '/software/profiles/rhel_6_4',
            name="sample-profile",
            path='/var'
        )
        self._add_item_to_model(
            'route',
            '/infrastructure/networking/routes/def_route',
            subnet='0.0.0.0/0', gateway='10.10.10.254')
        self._add_item_to_model(
            'storage-profile-base',
            '/infrastructure/storage/storage_profiles/profile_1',
        )

        # Create deployment
        self._add_item_to_model(
            "deployment",
            "/deployments/test")
        for i in range(1, num_of_clusters + 1):
            cluster_id = "123%d" % i
            self.add_cluster(num_of_nodes, cluster_type, cluster_id,
                             fencing_num, vcs_cluster_type,
                             cluster_name="cluster%d" % i,
                             ha_manager=ha_manager,
                             vcs_seed_threshold=vcs_seed_threshold,
                             app_agent_num_threads=app_agent_num_threads,
                             is_rack_cluster=is_rack_deployment)

        with mock.patch('litp.extensions.core_extension.MSValidator.get_hostname') as hostname:
            hostname.return_value = "ms1"
            self._update_item_in_model(
                '/ms',
                hostname='ms1'
            )
        self._add_item_to_model(
            'eth',
            '/ms/network_interfaces/if0',
            macaddress='08:00:27:5B:C2:AA',
            device_name='eth0',
            ipaddress='10.10.10.253',
            network_name='mgmt')
        self._add_item_to_model(
            'cobbler-service',
            '/ms/services/cobbler',
            pxe_boot_timeout=600,
            boot_mode='uefi' if is_rack_deployment else 'bios')

    def _set_model_applied(self):
        self.model.set_all_applied()

    def _add_service_to_model(self, number, servicename=None, csname=None,
                              active="1", standby="1", no_of_ips=1,
                              no_of_nodes=2,
                              cluster_type='vcs-clustered-service',
                              runtime=True):
        if servicename is None:
            servicename = number
        if csname is None:
            csname = 'cs%s' % number

        node_list = ','.join(["node{0}".format(x+1) for x in range(no_of_nodes)])

        self._add_item_to_model(
            cluster_type,
            '/deployments/test/clusters/cluster1/services/service%s' % number,
            name=csname,
            active=active,
            standby=standby,
            node_list=node_list
        )
        if runtime:
            cs_vpath = "/deployments/test/clusters/cluster1/services/" \
                       "service{0}/runtimes/runtime{0}".format(number)
            self._add_item_to_model(
                'lsb-runtime',
                cs_vpath,
                service_name=servicename,
                name="runtime{0}".format(number),
                restart_limit=3,
                startup_retry_limit=3,
                status_interval=30,
                status_timeout=60
            )
        else:
            service_vpath = "/software/services/service{0}".format(number)
            self._add_item_to_model(
                'service',
                service_vpath,
                service_name=servicename
            )
            cs_vpath = "/deployments/test/clusters/cluster1/services/" \
                       "service{0}".format(number)
            self._add_inherit_to_model(service_vpath,
                                       '%s/applications/app%s' % (cs_vpath,
                                                                  number))

        ips = []
        for ip in range(no_of_ips):
            ips.append(self._add_item_to_model(
                'vip',
                cs_vpath + "/ipaddresses/ip{0}".format(ip),
                network_name='mgmt',
                ipaddress='10.10.10.%d' % (ip + 51)
            ).ipaddress)
        return ips
