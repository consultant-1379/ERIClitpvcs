##############################################################################
# COPYRIGHT Ericsson AB 2014
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################
import mock
from collections import defaultdict
mock.patch('litp.core.litp_logging.LitpLogger').start()

from base_vcs_integration import VCSIntegrationBase
from vcsplugin.vcs_model import VCSModel


class TestVCSIntegration(VCSIntegrationBase):

    def setUp(self):
        super(TestVCSIntegration, self).setUp()

    def test_validate_model_1_ip(self):
        self.setup_model()
        self._add_service_to_model(1, no_of_ips=1)
        errors = self.plugin.validate_model(self.context_api)
        self.assertEqual(len(errors), 0)

    def test_create_configuration(self):
        self.setup_model()
        self._add_service_to_model(1, no_of_ips=1)
        tasks = self.plugin.create_configuration(self.context_api)
        self._print_task_descriptions(tasks)
        self.assertEqual(6, len(tasks))
        self.assertEqual(1, len(tasks[0].task_list))
        self.assertEqual(1, len(tasks[1].task_list))
        self.assertEqual(5, len(tasks[-1].task_list))

    def test_create_configuration_2_services(self):
        self.setup_model()
        self._add_service_to_model(1, no_of_ips=1)
        self._add_service_to_model(2, no_of_ips=1)
        tasks = self.plugin.create_configuration(self.context_api)
        self._print_task_descriptions(tasks)
        self.assertEqual(len(tasks), 6)
        self.assertEqual(len(tasks[0].task_list), 1)
        self.assertEqual(len(tasks[1].task_list), 1)
        self.assertEqual(len(tasks[-1].task_list), 9)

    def test_vcs_model_get_nics_no_gateway_because_no_network_host(self):
        self.setup_model()
        vcs_model = VCSModel(self.context_api)
        cluster = self.context_api.query("vcs-cluster")[0]
        nics = vcs_model.get_nic_groups(cluster)
        expected = defaultdict(dict)
        expected["eth0"]["mn1"] = None
        expected["eth0"]["mn2"] = None
        self.assertEqual(nics, expected)

    def test_vcs_model_get_nics_no_gateway_because_interface_is_for_removal(self):
        self.setup_model()
        vcs_model = VCSModel(self.context_api)
        cluster = self.context_api.query("vcs-cluster")[0]
        self._remove_item_from_model('/infrastructure/networking/routes/def_route')
        nics = vcs_model.get_nic_groups(cluster)
        expected = defaultdict(dict)
        expected["eth0"]["mn1"] = None
        expected["eth0"]["mn2"] = None
        self.assertEqual(nics, expected)

    def test_vcs_model_get_nics(self):
        self.setup_model()
        vcs_model = VCSModel(self.context_api)
        self._add_item_to_model(
            "vcs-network-host",
            "/deployments/test/clusters/cluster1/network_hosts/nh_1",
            network_name="mgmt",
            ip="10.10.10.11")
        cluster = self.context_api.query("vcs-cluster")[0]
        nics = vcs_model.get_nic_groups(cluster)
        expected = defaultdict(dict)
        expected["eth0"]["mn1"] = ['10.10.10.11']
        expected["eth0"]["mn2"] = ['10.10.10.11']
        self.assertEqual(nics, expected)

    def test_find_primary_node(self):
        # Verify that a Node is returned when the primary node is requested,
        # and that no node is returned if there is no node with node_id == 1
        self.setup_model()
        vcs_model = VCSModel(self.context_api)
        cluster = vcs_model._query("vcs-cluster")[0]
        node1 = vcs_model.find_primary_node(cluster)
        expected = '<QueryItem /deployments/test/clusters/cluster1/nodes/node1 [Initial]>'
        self.assertEqual(str(node1), expected)
        self._update_item_in_model("/deployments/test/clusters/cluster1/nodes/node1", node_id="3")
        node1 = vcs_model.find_primary_node(cluster)
        expected = None
        self.assertEqual(node1, expected)

    def test_initial_clustered_services(self):
        # verify that empty service list is returned if none are defined, then
        # non-empty list if one is added, two items if another added.
        # TODO: test what happens if one state is set to non-Initial (Is this even possible?)
        self.setup_model()
        vcs_model = VCSModel(self.context_api)

        service = vcs_model.initial_clustered_services()
        expected = []
        self.assertEqual(service, expected)

        self._add_service_to_model("1", "httpd", "cs1", "1", "1")
        service = vcs_model.initial_clustered_services()
        expected = ['<QueryItem /deployments/test/clusters/cluster1/services/service1 [Initial]>']
        self.assertEqual(self.string_and_sort(service), sorted(expected))
        self._add_service_to_model("2", "httpd", "cs2", "1", "1")

        service = vcs_model.initial_clustered_services()
        expected = ['<QueryItem /deployments/test/clusters/cluster1/services/service2 [Initial]>',
                    '<QueryItem /deployments/test/clusters/cluster1/services/service1 [Initial]>']
        self.assertEqual(self.string_and_sort(service), sorted(expected))

    def test_nodes_for_clustered_service(self):
        # verify that empty node list is returned if no clustered services are defined,
        # that a speific item is returned is specified clustered service exists,
        # and an empy list if a non-existent clustered service is requested
        self.setup_model()
        vcs_model = VCSModel(self.context_api)

        nodes = vcs_model.nodes_for_clustered_service("cs1")
        expected = None
        self.assertEqual(nodes, expected)

        self._add_service_to_model("1", "httpd", "cs1", "1", "1")
        nodes = vcs_model.nodes_for_clustered_service("cs1")
        expected = sorted(["<QueryItem /deployments/test/clusters/cluster1/nodes/node1 [Initial]>",
                           "<QueryItem /deployments/test/clusters/cluster1/nodes/node2 [Initial]>"])
        self.assertEqual(self.string_and_sort(nodes), expected)

        nodes = vcs_model.nodes_for_clustered_service("cs2")
        self.assertEqual(nodes, None)

    def test_packages_for_clustered_service(self):
        # verify that empty node list is returned if no clustered services are defined,
        # that a speific item is returned is specified clustered service exists,
        # and an empy list if a non-existent clustered service is requested
        self.setup_model()
        vcs_model = VCSModel(self.context_api)

        pkgs = vcs_model.packages_for_clustered_service("cs1")
        expected = None
        self.assertEqual(pkgs, expected)

        self._add_service_to_model("1", "httpd", "cs1", "1", "1")
        pkgs = vcs_model.packages_for_clustered_service("cs1")
        expected = '<QueryItem /deployments/test/clusters/cluster1/services/service1/runtimes/runtime1/packages [Initial]>'
        self.assertEqual(str(pkgs), expected)

        pkgs = vcs_model.packages_for_clustered_service("cs2")
        expected = None
        self.assertEqual(pkgs, expected)

    def test_is_node_server_type_rack(self):
        self.setup_model(is_rack_deployment=True)
        vcs_model = VCSModel(self.context_api)

        cluster = vcs_model._query("vcs-cluster")[0]
        node1 = vcs_model.find_primary_node(cluster)

        is_rack = vcs_model._is_node_server_type_rack(cluster, node1)
        self.assertEqual(is_rack, True)

    def test_hb_networks_info_for_node_blade(self):
        # verify that the hb networks are found if they exist, and not if they don't
        self.setup_model()
        vcs_model = VCSModel(self.context_api)

        cluster = vcs_model._query("vcs-cluster")[0]
        node1 = vcs_model.find_primary_node(cluster)

        # Heartbeat networks exist - return them
        hb_macs, _ = vcs_model._hb_networks_info_for_node(cluster, node1)
        expected = {'eth2': '08:00:27:5B:C1:31', 'eth1': '08:00:27:5B:C1:31', 'eth0': '08:00:27:5B:C1:31'}
        self.assertEqual(hb_macs, expected)

    def test_hb_networks_info_for_node_rack(self):
        self.setup_model(is_rack_deployment=True)
        vcs_model = VCSModel(self.context_api)

        cluster = vcs_model._query("vcs-cluster")[0]
        node1 = vcs_model.find_primary_node(cluster)

        # Heartbeat networks exist - return them
        _, hb_saps = vcs_model._hb_networks_info_for_node(cluster, node1, inc_low_prio=False, is_rack_node=True)
        expected = {'bond0.17': '0xcafc', 'bond0.91': '0xcafd'}
        self.assertEqual(hb_saps, expected)

    def test_hb_networks_info_for_node_rack_inc_low_prio(self):
        self.setup_model(is_rack_deployment=True)
        vcs_model = VCSModel(self.context_api)

        cluster = vcs_model._query("vcs-cluster")[0]
        node1 = vcs_model.find_primary_node(cluster)

        # Heartbeat networks exist - return them
        _, hb_saps = vcs_model._hb_networks_info_for_node(cluster, node1, inc_low_prio=True, is_rack_node=True)
        expected = {'bond0.17': '0xcafc', 'bond0.91': '0xcafd', 'br0': '0xcafe'}
        self.assertEqual(hb_saps, expected)

    def test_non_vcs_cluster(self):
        self.setup_model(cluster_type="cluster")
        tasks = self.plugin.create_configuration(self.context_api)
        for task in tasks:
            print task.description
        self.assertEqual(len(tasks), 0)

    def test_validate_model(self):
        self.setup_model()
        errors = self.plugin.validate_model(self.context_api)
        for error in errors:
            print error
        self.assertEqual(len(errors), 0)

    def test_LITPCDS_6161(self):
        # We just want to check that the validation all return empty lists
        # when there are no clusters in the model
        self.setup_model(num_of_nodes=0, num_of_clusters=0)
        errors = self.plugin.validate_model(self.context_api)
        self.assertEqual(len(errors), 0)
