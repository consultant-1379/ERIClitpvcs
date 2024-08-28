##############################################################################
# COPYRIGHT Ericsson AB 2014
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

import unittest
import mock

from litp.core.model_item import ModelItem
from litp.core.validators import ValidationError
from vcsplugin.app_resource import (ApplicationResource,
                             _get_update_error_message,
                             _check_updated_properties_on_item,
                             get_cyclic_dependencies)

class MockPlugin(object):
    def callback_method(self):
        pass

class TestVCSAppResource(unittest.TestCase):
    """
    Test suite for app_resource
    NOTE: This test suite is not exhaustive.
    """
    def setUp(self):
        self.helper = ApplicationResource(MockPlugin)
        self.callback_api = mock.Mock(is_running=lambda: True)

    @mock.patch("vcsplugin.app_resource.is_os_reinstall_on_peer_nodes")
    @mock.patch('vcsplugin.app_resource.is_being_deactivated')
    @mock.patch('vcsplugin.app_resource.get_updated_properties')
    @mock.patch('vcsplugin.app_resource.ApplicationResource._order_applications_by_dependency')
    @mock.patch('vcsplugin.app_resource.ApplicationResource._get_app_parameters')
    @mock.patch('vcsplugin.app_resource.is_clustered_service_redeploy_required')
    def test_create_configuration(self, is_redep_req, get_params,
                                  order_apps, get_props, being_deact,
                                  mock_os_reinstall):
        is_redep_req.return_value = True
        get_params.return_value = ("app1", "grp1", "vpaths")
        get_props.return_value = []
        being_deact.return_value = False
        mock_os_reinstall.return_value = False

        cluster = mock.Mock()
        cluster.is_for_removal.return_value = False
        haconfig = mock.Mock(is_updated=mock.Mock(return_value=False),
                             is_initial=mock.Mock(return_value=True),
                             service_id=None)
        haconfigs = mock.Mock(query=mock.Mock(return_value=[haconfig]))
        service = mock.Mock(is_initial=mock.Mock(return_value=False),
                            is_updated=mock.Mock(return_value=False),
                            ha_configs=haconfigs,
                            ipaddresses=[],
                            is_for_removal=mock.Mock(return_value=False))
        app = mock.Mock(is_initial=mock.Mock(return_value=False),
                        is_updated=mock.Mock(return_value=False))
        order_apps.return_value = [app]

        pre_tasks, post_tasks = self.helper.create_configuration(None, cluster, service)
        self.assertEqual(1, len(post_tasks))
        self.assertEqual(0, len(pre_tasks))
        self.assertEqual("Initial", post_tasks[0].state)
        self.assertEqual(post_tasks[0].kwargs,
                         {'callback_class': 'ApplicationResource',
                          'callback_func': 'cb_create_app',
                          'vpaths': 'vpaths'})

        is_redep_req.return_value = False
        pre_tasks, post_tasks = self.helper.create_configuration(None, cluster, service)
        self.assertEqual(0, len(post_tasks))
        self.assertEqual(1, len(pre_tasks))
        self.assertEqual("Initial", pre_tasks[0].state)
        self.assertEqual(pre_tasks[0].kwargs,
                         {'callback_class': 'ApplicationResource',
                          'callback_func': 'cb_update_app_before_lock',
                          'vpaths': 'vpaths'})

        service = mock.Mock(is_initial=mock.Mock(return_value=False),
                            is_updated=mock.Mock(return_value=True),
                            ha_configs=haconfigs,
                            ipaddresses=[],
                            is_for_removal=mock.Mock(return_value=False))
        post_lock_tasks, pre_lock_tasks = self.helper.create_configuration(
            None, cluster, service)
        self.assertEqual(1, len(post_lock_tasks))
        self.assertEqual(0, len(pre_lock_tasks))

    @mock.patch("vcsplugin.app_resource.is_os_reinstall_on_peer_nodes")
    @mock.patch('vcsplugin.app_resource.is_being_deactivated')
    @mock.patch('vcsplugin.app_resource.get_updated_properties')
    @mock.patch('vcsplugin.app_resource.ApplicationResource._order_applications_by_dependency')
    @mock.patch('vcsplugin.app_resource.ApplicationResource._get_app_parameters')
    @mock.patch('vcsplugin.app_resource.is_clustered_service_redeploy_required')
    def test_create_configuration_applied_service(self, is_redep_req,
                                                  get_params, order_apps,
                                                  get_props, being_deact,
                                                  mock_os_reinstall):
        is_redep_req.return_value = False
        get_params.return_value = ("app1", "grp1", "vpaths")
        get_props.return_value = []
        being_deact.return_value = False
        mock_os_reinstall.return_value = False

        cluster = mock.Mock(item_id="cluster")
        cluster.is_for_removal.return_value = False
        haconfig = mock.Mock(is_updated=mock.Mock(return_value=False),
                             is_initial=mock.Mock(return_value=False),
                             service_id=None,
                             dependency_list=None)
        haconfigs = mock.Mock(query=mock.Mock(return_value=[haconfig]))
        service = mock.Mock(is_initial=mock.Mock(return_value=False),
                            is_updated=mock.Mock(return_value=False),
                            ha_configs=haconfigs,
                            item_id="service",
                            get_vpath=lambda: "vpath",
                            ipaddresses=[
                                mock.Mock(ipaddress='1.1.1.1',
                                          network_name='foo'),
                                mock.Mock(ipaddress='2.2.2.2',
                                          network_name='foo')
                            ],
                            is_for_removal=mock.Mock(return_value=False))
        app = mock.Mock(is_initial=mock.Mock(return_value=False),
                        is_updated=mock.Mock(return_value=False))
        order_apps.return_value = [app]

        pre_tasks, post_tasks = self.helper.create_configuration(None, cluster, service)
        self.assertEqual(0, len(post_tasks))
        self.assertEqual(2, len(pre_tasks))
        self.assertEqual("Initial", pre_tasks[0].state)
        self.assertEqual("Initial", pre_tasks[1].state)
        self.assertEqual({'callback_class': 'ApplicationResource',
                          'callback_func': 'cb_link_vips_to_app',
                          'vpaths': 'vpaths'},
                         pre_tasks[0].kwargs)
        self.assertEqual({'callback_class': 'VcsSGOnlineHelper',
                          'callback_func': 'online_callback',
                          'service_vpath': 'vpath',
                          'vcs_grp_name': 'Grp_CS_cluster_service'},
                         pre_tasks[1].kwargs)

    @mock.patch('vcsplugin.app_resource.get_updated_properties')
    @mock.patch('vcsplugin.app_resource.ApplicationResource._order_applications_by_dependency')
    @mock.patch('vcsplugin.app_resource.ApplicationResource._get_app_parameters')
    @mock.patch('vcsplugin.app_resource.is_clustered_service_redeploy_required')
    def test_create_configuration_initial_apd_false(self, srv_redeploy_req, get_params,
                                                    order_apps, get_props):
        get_params.return_value = ("app1", "grp1", "vpaths")
        get_props.return_value = []
        srv_redeploy_req = False

        cluster = mock.Mock()
        cluster.is_for_removal.return_value = False
        haconfig = mock.Mock(is_updated=mock.Mock(return_value=False),
                             is_initial=mock.Mock(return_value=True),
                             service_id=None)
        haconfigs = mock.Mock(query=mock.Mock(return_value=[haconfig]))
        service = mock.Mock(is_initial=mock.Mock(return_value=True),
                            is_updated=mock.Mock(return_value=False),
                            ha_configs=haconfigs,
                            ipaddresses=[],
                            applied_properties_determinable=False,
                            is_for_removal=mock.Mock(return_value=False))
        app = mock.Mock(is_initial=mock.Mock(return_value=True),
                        is_updated=mock.Mock(return_value=False))
        order_apps.return_value = [app]

        pre_tasks, post_tasks = self.helper.create_configuration(None, cluster,
                                                                 service)
        self.assertEqual(1, len(post_tasks))
        self.assertEqual(0, len(pre_tasks))

    @mock.patch("vcsplugin.app_resource.is_os_reinstall_on_peer_nodes")
    @mock.patch('vcsplugin.app_resource.is_being_deactivated')
    @mock.patch('vcsplugin.app_resource.ApplicationResource._order_applications_by_dependency')
    @mock.patch('vcsplugin.app_resource.ApplicationResource._get_app_parameters')
    @mock.patch('vcsplugin.app_resource.is_clustered_service_redeploy_required')
    def test_create_configuration_app_updated(self, is_redep_req, get_params,
                                              order_apps, being_deact,
                                              mock_os_reinstall):
        is_redep_req.return_value = True
        get_params.return_value = ("app1", "grp1", "vpaths")
        being_deact.return_value = False
        mock_os_reinstall.return_value = False

        cluster = mock.Mock()
        cluster.is_for_removal.return_value = False
        haconfigs = mock.Mock(query=mock.Mock(return_value=[]))

        app = mock.Mock(cleanup_command="new command")
        app.is_initial.return_value = False
        app.applied_properties = {'cleanup_command': 'old command'}

        order_apps.return_value = [app]

        is_redep_req.return_value = False
        service = mock.Mock(is_initial=mock.Mock(return_value=False),
                            is_updated=mock.Mock(return_value=True),
                            ha_configs=haconfigs,
                            ipaddresses=[],
                            is_for_removal=mock.Mock(return_value=False))

        pre_tasks, post_tasks = self.helper.create_configuration(
            None, cluster, service)

        self.assertEqual(1, len(pre_tasks))
        self.assertEqual(1, len(post_tasks))
        self.assertEqual("Initial", post_tasks[0].state)
        self.assertEqual({'callback_class': 'ApplicationResource',
                          'callback_func': 'cb_update_app_after_lock',
                          'vpaths': 'vpaths'}, post_tasks[0].kwargs)
        self.assertNotIn('cleanup_command', pre_tasks[0].description)
        self.assertIn('cleanup_command', post_tasks[0].description)

        mock_os_reinstall.return_value = True
        pre_tasks, post_tasks = self.helper.create_configuration(
            None, cluster, service)
        self.assertEqual(1, len(pre_tasks))

        self.assertEqual("Initial", pre_tasks[0].state)
        self.assertEqual({'callback_class': 'ApplicationResource',
                          'callback_func': 'cb_update_app_before_lock',
                          'vpaths': 'vpaths'}, pre_tasks[0].kwargs)
        self.assertIn('cleanup_command', pre_tasks[0].description)

    def test_get_wrapper_command_pos_01(self):
        self.helper._get_resource_check_delay = lambda: 13
        cmd = "start"
        service_name = "mocklsb"
        self.assertEquals("/usr/share/litp/vcs_lsb_start mocklsb 13",
                self.helper._get_wrapper_command(service_name, cmd))

    @mock.patch("vcsplugin.vcs_utils.is_os_reinstall_on_peer_nodes")
    @mock.patch("vcsplugin.vcs_base_helper.is_os_reinstall_on_peer_nodes")
    @mock.patch('vcsplugin.app_resource.ApplicationResource._get_appres_parameters')
    def test_cb_link_vips_to_app(self, get_params, mock_os_reinstall,
                                 os_reinstall):
        vcs_api = mock.Mock()
        vcs_api.readable_conf = mock.MagicMock()
        self.helper._vcs_api = vcs_api
        res_name = 'res_name'
        mock_os_reinstall.return_value = False
        os_reinstall.return_value = False

        cluster = mock.Mock(item_id='cluster')
        node1 = mock.Mock(hostname="n1")
        haconfigs = mock.Mock(query=mock.Mock(return_value=[]))
        app = mock.Mock(item_id='app')
        service = mock.Mock(active=1,standby=0,
                            is_initial=mock.Mock(return_value=False),
                            is_updated=mock.Mock(return_value=False),
                            nodes=[node1],
                            applications=[app],
                            item_id='service',
                            node_list="n1",
                            applied_properties={"node_list":"n1"},
                            ipaddresses=[
                                mock.Mock(ipaddress='1.1.1.1', network_name='foo'),
                                mock.Mock(ipaddress='2.2.2.2', network_name='foo')
                            ],
                            ha_configs=haconfigs)

        get_params.return_value = (res_name, cluster, service, app)

        self.helper.cb_link_vips_to_app(vcs_api, [])
        vcs_api.hares_link.assert_has_calls([
            mock.call(parent=res_name, child='Res_IP_cluster_service_app_foo_1'),
            mock.call(parent=res_name, child='Res_IP_cluster_service_app_foo_2')])

    @mock.patch("vcsplugin.vcs_base_helper.is_os_reinstall_on_peer_nodes")
    def test_create_app_dependencies(self, mock_os_reinstall):
        vcs_api = mock.Mock()
        self.helper.nodes = ["n1"]
        self.helper._vcs_api = vcs_api
        ha_configs = mock.MagicMock()
        mock_os_reinstall.return_value = False
        ####expand coverage
        service = mock.Mock(ipaddresses=[
                        mock.Mock(ipaddress='1.1.1.1', network_name='foo'),
                        mock.Mock(ipaddress='2.2.2.2', network_name='foo')
                        ], applications=[mock.Mock(item_id='app')],
                    ha_configs=ha_configs, item_id='service',
                    active=1, standby=1,
                    node_list="n1",
                    applied_properties={'standby':1,'active':1,
                                        'node_list':'n1'},
                    nodes = [mock.Mock()]
                    )
        cluster = mock.Mock(item_id='cluster')
        res_name = 'res_name'

        self.helper._create_app_dependencies(
            self.callback_api, res_name, cluster, service, mock.Mock())
        vcs_api.hares_link.assert_has_calls([
            mock.call(parent=res_name, child='Res_IP_cluster_service_app_foo_1'),
            mock.call(parent=res_name, child='Res_IP_cluster_service_app_foo_2')],
            any_order=True)

    @mock.patch("vcsplugin.vcs_base_helper.is_os_reinstall_on_peer_nodes")
    def test_create_empty_app_dependencies(self, mock_os_reinstall):
        mock_os_reinstall.return_value = False
        vcs_api = mock.Mock()
        self.helper.nodes = ["n1"]
        self.helper._vcs_api = vcs_api
        ha_configs = mock.MagicMock()
        ha_configs.query.return_value = [mock.Mock(dependency_list='',
                                                   service_id='app')]
        app = mock.Mock(item_id='app')
        service = mock.Mock(name='service', ipaddresses=[
            mock.Mock(ipaddress='1.1.1.1', network_name='foo'),
            mock.Mock(ipaddress='2.2.2.2', network_name='foo')],
            ha_configs=ha_configs, item_id='service',
            applied_properties={'active':1,'standby':1, 'node_list':'n1'},
            active=1, standby=1,
            node_list="n1",
            applications=[app], nodes=[mock.Mock()])
        cluster = mock.Mock(item_id='cluster')
        res_name = 'res_name'

        self.helper._create_app_dependencies(
            self.callback_api, res_name, cluster, service, app)
        vcs_api.hares_link.assert_has_calls([
            mock.call(parent=res_name, child='Res_IP_cluster_service_app_foo_1'),
            mock.call(parent=res_name, child='Res_IP_cluster_service_app_foo_2')],
            any_order=True)

    @mock.patch('vcsplugin.app_resource.select_nodes_from_service')
    @mock.patch('vcsplugin.app_resource.get_ha_app_config')
    @mock.patch("vcsplugin.app_resource.is_os_reinstall_on_peer_nodes")
    @mock.patch(
        'vcsplugin.app_resource.ApplicationResource._get_appres_parameters')
    def test_cb_update_app_before_lock(self, get_params, mock_os_reinstall,
                                       mock_get_ha_app_config,
                                       mock_select_nodes_from_service):

        mock_get_ha_app_config.return_value = None
        res_name = 'res_name'

        vcs_api = mock.Mock()
        vcs_api.readable_conf = mock.MagicMock()
        self.helper._vcs_api = vcs_api

        cluster = mock.Mock(item_id='cluster')
        service = mock.Mock(item_id='service')
        app = mock.Mock(is_updated=mock.Mock(return_value=True),
                        get_vpath=lambda: "app_vpath",
                        start_command="new command",
                        stop_command="new command",
                        status_command="new command",
                        service_name="new name")

        get_params.return_value = (res_name, cluster, service, app)
        self.helper._modify_app_resource = mock.MagicMock()

        mock_os_reinstall.return_value = False
        self.helper.cb_update_app_before_lock(self.callback_api, app)
        self.assertNotIn('cleanup_program',
                         self.helper._modify_app_resource.call_args[1])

        mock_os_reinstall.return_value = True
        self.helper.cb_update_app_before_lock(self.callback_api, app)
        self.assertIn('cleanup_program',
                      self.helper._modify_app_resource.call_args[1])

    def test_get_wrapper_command_pos_02(self):
        self.helper._get_resource_check_delay = lambda: 15
        cmd = "stop"
        service_name = "mocklsb"
        self.assertEquals("/usr/share/litp/vcs_lsb_stop mocklsb 15",
                self.helper._get_wrapper_command(service_name, cmd))

    def test_get_wrapper_command_pos_03(self):
        cmd = "status"
        service_name = "mocklsb"
        self.assertEquals("/usr/share/litp/vcs_lsb_status mocklsb",
                self.helper._get_wrapper_command(service_name, cmd))

    def test_get_wrapper_command_pos_04(self):
        cmd = "vm_status"
        service_name = "mocklsb"
        self.assertEquals("/usr/share/litp/vcs_lsb_vm_status mocklsb",
                self.helper._get_wrapper_command(service_name, cmd))

    def test__check_ha_service_config(self):
        s1 = mock.Mock()
        conf1, conf2 = mock.Mock(), mock.Mock()
        s1.query.return_value = [conf1, conf2]
        s1.item_id = "ser1"
        s1.applications = [mock.Mock()]
        s1.get_vpath.return_value = "s1_vpath"
        s1.name = "cs1"
        s1.is_for_removal.return_value = False
        errs = self.helper._validate_ha_service_config(s1)
        msg = ('Number of ha-service-config items defined for '
               'vcs-clustered-service "cs1" exceeds maximum number of 1')
        expected = ValidationError(
                        item_path="s1_vpath",
                        error_message=msg)
        self.assertEqual(expected, errs[0])
        self.assertEqual(1, len(errs))

    def test_check_for_duplicate_apps_in_same_cs(self):
        # test for one-node parallel service group with 2 apps
        # that both have the same service_name
        app1, app2 = mock.Mock(), mock.Mock()
        app1.item_id = "app1"
        app2.item_id = "app2"
        app1.service_name = "app1_name"
        app2.service_name = "app1_name"
        serv = mock.Mock()
        serv.applications = [app1, app2]
        serv.active = "1"
        serv.standby = "0"
        serv.name = "cs1"
        serv.vpath = "s_vpath"
        serv.is_for_removal.return_value = False
        errs = self.helper._validate_for_duplicate_apps_in_same_cs(serv)
        msg = ('Clustered service "{0}" attempts to start '
               'service "{1}" in multiple service items {2}'
               .format(serv.name, app1.service_name,
               ", ".join('"{0}"'.format(item_id) for item_id in
                                      [app1.item_id, app2.item_id])))
        expected = ValidationError(
                        item_path=serv.vpath,
                        error_message=msg)
        self.assertEqual(expected, errs[0])
        self.assertEqual(1, len(errs))

    def test_check_failover_apps_all_have_ha_service_configs(self):
        # test for one-node parallel service group with 2 apps
        # and no ha_configs
        app1, app2 = mock.Mock(), mock.Mock()
        app1.item_id = "app1"
        app2.item_id = "app2"
        ha_conf = mock.Mock()
        ha_conf.query.return_value = []
        serv = mock.Mock()
        serv.active = "1"
        serv.standby = "0"
        serv.applications = [app1, app2]
        serv.ha_configs = ha_conf
        serv.vpath = "s_vpath"
        serv.is_for_removal.return_value = False
        errs = self.helper._validate_failover_apps_all_have_ha_service_configs(serv)
        msg = ('No ha-service-config item exists for application '
                                   '"{0}"'.format(app1.item_id))
        expected = ValidationError(item_path=serv.vpath,
                                   error_message=msg)
        self.assertEqual(expected, errs[0])
        self.assertEqual(2, len(errs))

        # test for failover service group with 2 apps and no ha_configs
        serv.standby = "1"
        errs = self.helper._validate_failover_apps_all_have_ha_service_configs(serv)
        msg = ('No ha-service-config item exists for application '
                                   '"{0}"'.format(app1.item_id))
        expected = ValidationError(item_path=serv.vpath,
                                   error_message=msg)
        self.assertEqual(expected, errs[0])
        self.assertEqual(2, len(errs))

        # test for failover service group with 2 apps and
        # 2 ha_configs per app
        conf1, conf2 = mock.Mock(), mock.Mock()
        conf1.vpath = "conf1_vpath"
        conf2.vpath = "conf2_vpath"
        ha_conf.query.return_value = [conf1, conf2]
        errs = self.helper._validate_failover_apps_all_have_ha_service_configs(serv)
        msg = ('Too many ha-service-config items for '
               'application "{0}"'.format(app1.item_id))
        expected = ValidationError(item_path=conf1.vpath,
                                   error_message=msg)
        self.assertEqual(expected, errs[0])
        self.assertEqual(4, len(errs))

        # test for one node parallel service group with 2 apps and
        # 1 ha_config per app
        serv.standby = "1"
        conf = mock.Mock(), mock.Mock()
        ha_conf.query.return_value = [conf]
        errs = self.helper._validate_failover_apps_all_have_ha_service_configs(serv)
        self.assertEqual(0, len(errs))

    def test_check_parallel_services_dont_specify_dependencies(self):
        # test no error is returned for multi-node parallel
        # service group with no dependency_list
        ha_conf = mock.Mock(vpath="s_vpath", dependency_list="")
        ha_conf.query.return_value = []
        serv = mock.Mock(active="2", standby="0")
        serv.ha_configs.query.return_value = [ha_conf]
        serv.is_for_removal.return_value = False
        errs = self.helper._validate_parallel_services_dont_specify_dependencies(serv)
        self.assertEqual(0, len(errs))

        # test error is returned for multi-node parallel
        # service group with a dependency_list
        ha_conf.dependency_list = "any"
        errs = self.helper._validate_parallel_services_dont_specify_dependencies(serv)
        msg = ('A dependency_list property can only be specified for the '
               'ha-service-config item in a failover or a one node parallel '
               'vcs-clustered-service.')
        expected = ValidationError(item_path=ha_conf.vpath,
                                   error_message=msg)
        self.assertEqual(expected, errs[0])
        self.assertEqual(1, len(errs))

        # test no error is returned for one node parallel
        # service group with a dependency_list
        serv.active = "1"
        errs = self.helper._validate_parallel_services_dont_specify_dependencies(serv)
        self.assertEqual(0, len(errs))

    def test__get_dependency_list_empty(self):
        app = mock.Mock()
        service = mock.Mock()
        service.ha_configs.query.return_value = []
        self.assertEqual([], self.helper._get_dependency_list(app, service))

    def test__get_dependency_list_full(self):
        app = mock.Mock(dependency_list='a,b')
        service = mock.Mock()
        service.ha_configs.query.return_value = [app]
        self.assertEqual(['a', 'b'], self.helper._get_dependency_list(app, service))

    @mock.patch('vcsplugin.app_resource.ApplicationResource._get_dependency_list')
    def test__order_applications_by_dependency(self, __get_dependency_list):
        __get_dependency_list.side_effect = [[], ['app1', 'app3'], ['app1']]
        app1 = mock.Mock(item_id='app1')
        app2 = mock.Mock(item_id='app2')
        app3 = mock.Mock(item_id='app3')

        service = mock.Mock()
        service.applications = [app1, app2, app3]
        ids = [app.item_id for app in self.helper._order_applications_by_dependency(service)]
        self.assertEqual(['app1', 'app3', 'app2'], ids)

    def test__get_update_error_message(self):
        msg = _get_update_error_message(('foo',))
        self.assertEqual('The following property cannot be updated: "foo".', msg)
        msg = _get_update_error_message(('bar', 'baz'))
        self.assertEqual('The following properties cannot be updated: "bar", "baz".', msg)

    @mock.patch('vcsplugin.app_resource._check_updated_properties')
    def test__check_updated_properties_on_item(self, check_updated_properties):
        item = mock.Mock()
        item.get_vpath.return_value = 'foo'

        check_updated_properties.return_value = ['baz']
        result = _check_updated_properties_on_item(['bar'], item)
        expected = [ValidationError(item_path='foo', error_message='The following property cannot be updated: "baz".')]
        self.assertEqual(expected, result)

        check_updated_properties.return_value = []
        result = _check_updated_properties_on_item(['bar'], item)
        self.assertEqual([], result)

    @mock.patch('vcsplugin.app_resource.is_os_reinstall_on_peer_nodes')
    def test__validate_updated_properties(self, is_os_reinstall_on_peer_nodes):
        properties = ['start_command', 'stop_command',
                      'status_command', 'service_name']
        app = mock.Mock(is_updated=mock.Mock(return_value=True),
                        get_vpath=lambda: "app_vpath",
                        start_command="new command",
                        stop_command="new command",
                        status_command="new command",
                        service_name="new name")
        app.applied_properties = {'start_command': 'old command',
                                  'stop_command': 'old command',
                                  'status_command': 'old command',
                                  'service_name': 'old name'}
        service = mock.Mock(is_updated=mock.Mock(return_value=False),
                            applications=[app])

        is_os_reinstall_on_peer_nodes.return_value = False
        errs = self.helper._validate_updated_properties(service)
        msg = 'The following properties cannot be updated: {0}.'.\
            format(", ".join('"{0}"'.format(prop) for prop in properties))
        expected = [ValidationError(item_path=app.get_vpath(),
                                    error_message=msg)]
        self.assertEqual(expected, errs)
        self.assertEqual(1, len(errs))

        is_os_reinstall_on_peer_nodes.return_value = True
        errs = self.helper._validate_updated_properties(service)
        msg = 'The following property cannot be updated: "{0}".'.\
            format(properties[-1])
        expected = [ValidationError(item_path=app.get_vpath(),
                                    error_message=msg)]
        self.assertEqual(expected, errs)
        self.assertEqual(1, len(errs))

    @mock.patch('vcsplugin.app_resource._get_all_app_ids')
    def test_get_cyclic_dependencies_ignores_app_without_config(self, app_ids):
        app_ids.return_value = ['httpd_service', 'test_service1',
                                'test_service2']
        service = mock.Mock()
        service.query.return_value = [mock.Mock(service_id='httpd_service',
                                                dependency_list='test_service1,test_service2'),
                                      mock.Mock(service_id='test_service1',
                                                dependency_list='test_service2')
                                     ]
        self.assertEquals([], get_cyclic_dependencies(service))

    @mock.patch('vcsplugin.app_resource._get_all_app_ids')
    def test_get_cyclic_dependencies_no_config_still_detects_cycles(self, app_ids):
        app_ids.return_value = ['httpd_service', 'test_service1',
                                'test_service2']
        service = mock.Mock()
        service.query.return_value = [mock.Mock(service_id='httpd_service',
                                                dependency_list='test_service1,test_service2'),
                                      mock.Mock(service_id='test_service1',
                                                dependency_list='httpd_service,test_service2')
                                     ]
        self.assertEquals(set(['httpd_service','test_service1']),
                          set(get_cyclic_dependencies(service)))


class TestAddAppResource(unittest.TestCase):
    # Class for testing AppResource._get_app_resource
    def setUp(self):
        self.helper = ApplicationResource(mock.Mock())
        self.ha_app_conf = mock.Mock(spec=ModelItem)
        self.ha_app_conf.fault_on_monitor_timeouts = "fault_on_monitor_timeout"
        self.ha_app_conf.tolerance_limit = "tolerance_limit"
        self.ha_app_conf.clean_timeout = "clean_timeout"
        self.ha_app_conf.status_interval = "status_interval"
        self.ha_app_conf.status_timeout = "status_timeout"
        self.ha_app_conf.restart_limit = "restart_limit"
        self.ha_app_conf.startup_retry_limit = "startup_retry_limit"

    def test__add_app_resource_adds_cleanup_program(self):
        resource_name = "Res_App_c1_groupname_appname"
        group_name = "Grp_CS_c1_groupname_appname"
        start_program = "/bin/rm -rf /"
        cleanup_program = "/bin/service start"
        stop_program = "/bin/service stop"
        status_program = "/bin/service status"
        vcs_cmd_api = mock.Mock()
        self.helper.nodes = ["n1"]
        self.helper._vcs_api = vcs_cmd_api
        self.helper._add_app_resource(resource_name, group_name,
                                      start_program, stop_program,
                                      status_program, cleanup_program,
                                      'app_online_timeout',
                                      'app_offline_timeout', self.ha_app_conf)

        overrite_calls = [mock.call(resource_name, "CleanProgram"),
                          mock.call(resource_name, "FaultOnMonitorTimeouts"),
                          mock.call(resource_name, "ToleranceLimit"),
                          mock.call(resource_name, "CleanTimeout"),
                          mock.call(resource_name, "MonitorInterval"),
                          mock.call(resource_name, "MonitorTimeout"),
                          mock.call(resource_name, "RestartLimit"),
                          mock.call(resource_name, "OnlineRetryLimit"),
                          mock.call(resource_name, "OnlineTimeout"),
                          mock.call(resource_name, "OfflineTimeout")
                          ]

        modify_calls = [mock.call(resource_name, "Critical", '1'),
                        mock.call(resource_name, "StartProgram",
                                  "'%s'" % start_program),
                        mock.call(resource_name, "StopProgram",
                                  "'%s'" % stop_program),
                        mock.call(resource_name, "MonitorProgram",
                                  "'%s'" % status_program),
                        mock.call(resource_name, "CleanProgram",
                                  "'%s'" % cleanup_program),
                        mock.call(resource_name, "FaultOnMonitorTimeouts",
                                  "'%s'" % self.ha_app_conf.fault_on_monitor_timeouts),
                        mock.call(resource_name, "ToleranceLimit",
                                  "'%s'" % self.ha_app_conf.tolerance_limit),
                        mock.call(resource_name, "CleanTimeout",
                                  "'%s'" % self.ha_app_conf.clean_timeout),
                        mock.call(resource_name, "MonitorInterval",
                                  "'%s'" % self.ha_app_conf.status_interval),
                        mock.call(resource_name, "MonitorTimeout",
                                  "'%s'" % self.ha_app_conf.status_timeout),
                        mock.call(resource_name, "RestartLimit",
                                  "'%s'" % self.ha_app_conf.restart_limit),
                        mock.call(resource_name, "OnlineRetryLimit",
                                  "'%s'" % self.ha_app_conf.startup_retry_limit),
                        mock.call(resource_name, "OnlineTimeout",
                                  "'%s'" % 'app_online_timeout'),
                        mock.call(resource_name, "OfflineTimeout",
                                  "'%s'" % 'app_offline_timeout')]

        vcs_cmd_api.hares_add.assert_has_calls(mock.call(resource_name,
                                                           "Application",
                                                           group_name))
        vcs_cmd_api.hares_override_attribute.assert_has_calls(overrite_calls,
                                                              any_order=True)

        vcs_cmd_api.hares_modify.assert_has_calls(modify_calls, any_order=True)

        self.assertEqual(13, vcs_cmd_api.hares_override_attribute.call_count)
        self.assertEqual(15, vcs_cmd_api.hares_modify.call_count)

    def test__add_app_resource_does_not_set_app_online_timeout_on_none(self):
        none_app_online_timeout = None
        vcs_cmd_api = mock.Mock()
        self.helper.nodes = ["n1"]
        self.helper._vcs_api = vcs_cmd_api
        self.helper._add_app_resource('resource_name', 'group_name',
                                      'start_program', 'stop_program',
                                      'status_program', 'cleanup_program',
                                      'app_online_timeout',
                                      none_app_online_timeout,
                                      self.ha_app_conf)
        # Check that assert_any_call raises an AssertError
        self.assertRaises(AssertionError,
                          vcs_cmd_api.hares_override_attribute.assert_any_call,
                          'resource', 'OnlineTimeout')
        self.assertRaises(AssertionError,
                          vcs_cmd_api.hares_modify.assert_any_call,
                          'resource', 'OnlineTimeout', "'None'")

    def test__add_app_resource_does_not_set_app_offline_timeout_on_none(self):
        noe_app_offline_timeout = None
        vcs_cmd_api = mock.Mock()
        self.helper.nodes = ["n1"]
        self.helper._vcs_api = vcs_cmd_api
        self.helper._add_app_resource('resource_name', 'group_name',
                                      'start_program', 'stop_program',
                                      'status_program', 'cleanup_program',
                                      'app_online_timeout',
                                      noe_app_offline_timeout,
                                      self.ha_app_conf)
        # Check that assert_any_call raises an AssertError
        self.assertRaises(AssertionError,
                          vcs_cmd_api.hares_override_attribute.assert_any_call,
                          'resource', 'OfflineTimeout')

        self.assertRaises(AssertionError,
                          vcs_cmd_api.hares_modify.assert_any_call,
                          'resource', 'OfflineTimeout', "'None'")

