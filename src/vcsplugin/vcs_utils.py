##############################################################################
# COPYRIGHT Ericsson AB 2014
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################


from collections import namedtuple
from itertools import groupby
import time
import netaddr
from litp.core.litp_logging import LitpLogger
from litp.core.execution_manager import PlanStoppedException
from vcsplugin.vcs_constants import (PLAN_STOPPED_MESSAGE,
                                     DEFAULT_IPV6_PREFIXLEN)

log = LitpLogger()

STEP_SIZE = 10
DEFAULT_SLEEP_TIME = 1
DEFAULT_MAX_WAIT_TIME = 60 * 3


class ShowTimeElapsed(object):
    def __init__(self, function_name):
        self.function_name = function_name

        self.start_time = int(time.time())
        self.step_number = 0

    def log(self):
        time_since_start = int(time.time()) - self.start_time
        if time_since_start / STEP_SIZE != self.step_number:
            self.step_number += 1
            log.trace.debug('Waiting for {0}. {1} seconds elapsed'.format(
                self.function_name, self.step_number * STEP_SIZE))


def group(iterable, key=None):
    """
    Utility function for grouping together items based on an
    optional `key` function.

    Returns a `dict` with key being the attribute the items
    have been grouped by and values being a `tuple` of items
    which have been grouped.
    """
    # If `key` is `None` we use an identity function.
    if key is None:
        key = lambda _: _
    groups = groupby(sorted(iterable, key=key), key)
    return dict((k, tuple(v)) for k, v in groups)


# It is used to keep some of the parameters for wait_on_state function.
# His purpose is only to make us life easy when we use wait_on_state
TimeoutParameters = namedtuple('TimeoutParameters',
                           'max_wait sleep_function sleep_time interruptible')
TimeoutParameters.__new__.__defaults__ = (DEFAULT_MAX_WAIT_TIME,
                                          time.sleep,
                                          DEFAULT_SLEEP_TIME,
                                          True)


class VcsUtils(object):
    def get_dependency_tree(self, clustered_service_items,
                            include_initial_deps=False):
        """
        :param clustered_service_items: (list of objects) clustered_services
        :param include_initial_deps: (boolean) If True, also include initial
            dependencies in the dictionary
        :return: A dictionary with the dependency tree
        """
        dependency_tree = {}
        for service in clustered_service_items:
            if service.dependency_list:
                dependency_tree[service.item_id] = (service.dependency_list.
                                                    split(','))
            else:
                dependency_tree[service.item_id] = []

        if include_initial_deps:
            for service in clustered_service_items:
                if service.initial_online_dependency_list:
                    dependency_tree[service.item_id].extend(
                        service.initial_online_dependency_list.split(','))

        return dependency_tree

    def get_dependency_tree_initial_deps(self, clustered_service_items):
        """
        :param clustered_service_items: (list of objects) clustered_services
        :return: A dictionary with the initial dependency tree
        """
        dependency_tree = {}
        for service in clustered_service_items:
            if service.initial_online_dependency_list:
                dependency_tree[service.item_id] = (
                    service.initial_online_dependency_list.split(','))
            else:
                dependency_tree[service.item_id] = []

        return dependency_tree

    def get_dependency_tree_applied(self, clustered_service_items):
        dependency_tree = {}

        for service in clustered_service_items:
            if service.applied_properties.get('dependency_list'):
                dependency_tree[service.item_id] = (
                    service.applied_properties['dependency_list'].split(','))
            else:
                dependency_tree[service.item_id] = []

        return dependency_tree

    def _order_service_creation(self, ordered_item_ids,
                                clustered_service_items, reverse=False):
        return sorted(
            clustered_service_items,
            key=lambda service: ordered_item_ids.index(service.item_id),
            reverse=reverse)

    def _get_ordered_item_ids(self, dependency_tree):
        ordered_item_ids = []
        while dependency_tree:
            to_remove = [k for k, v in dependency_tree.iteritems() if not v]

            for node, leaf_nodes in dependency_tree.items():
                if node in to_remove and not dependency_tree[node]:
                    del dependency_tree[node]
                else:
                    # Delete the relevent node_leaves from the node
                    dependency_tree[node] = set(leaf_nodes).difference(
                        to_remove)

            ordered_item_ids.extend(sorted(to_remove))
        return ordered_item_ids

    def get_ordered_sg_creation(self, clustered_service_items):
        # Creation order is determined by dependent service groups being
        # created first. If two service groups are at the same level in the
        # dependency tree, then the groups are created alphabetically
        services = [service for service in clustered_service_items
                    if not service.is_for_removal()]
        dependency_tree = self.get_dependency_tree(services,
                                                   include_initial_deps=True)
        ordered_item_ids = self._get_ordered_item_ids(dependency_tree)

        return self._order_service_creation(ordered_item_ids,
                                            services)

    def get_ordered_sg_removal(self, clustered_service_items):
        # Removal order is determined by dependent service groups being
        # created second. So the dependencies are removed before the dependent
        # service group is removed, using the applied property dependency_list
        dependency_tree = self.get_dependency_tree_applied(
            clustered_service_items)
        ordered_item_ids = self._get_ordered_item_ids(dependency_tree)

        return self._order_service_creation(ordered_item_ids,
                                            clustered_service_items,
                                            reverse=True)

    def filter_node_hostnames(self, nodes, node_item_ids):
        hostnames = []
        for node in nodes:
            if node.item_id in node_item_ids:
                hostnames.append(node.hostname)
        return hostnames

    @staticmethod
    def get_service_online_time(service):
        service_online_time = int(service.online_timeout)
        max_online_retry_limit = max([0] + [int(hacfg.startup_retry_limit or 0)
                                            for hacfg in
                                            service.query("ha-service-config")]
                                            )
        return service_online_time * (max_online_retry_limit + 1)

    @staticmethod
    def wait_on_state(callback_api, callback_function, timing_parameters,
                      *callback_args, **callback_kwargs):
        """
        Blocking method that returns True when a state is reached or
        if the timeout is exceeded returns False.
        """
        start_time = int(time.time())
        log.trace.debug('Timeout for "{0}" is set to {1} seconds.'.format(
            callback_function.__name__, timing_parameters.max_wait))

        show_elapsed_time = ShowTimeElapsed(callback_function.__name__)
        while not callback_function(*callback_args, **callback_kwargs):
            # If the task is marked as interruptible, check if the LITP
            # daemon is planning to stop.
            if (timing_parameters.interruptible and
                    not callback_api.is_running()):
                raise PlanStoppedException(PLAN_STOPPED_MESSAGE)
            show_elapsed_time.log()
            diff_time = int(time.time()) - start_time

            if diff_time > timing_parameters.max_wait:
                return False
            timing_parameters.sleep_function(timing_parameters.sleep_time)
        return True

    def attach_child_items_to_task(self, task, service):
        """
        Attaches the child items to the vcs-clustered-service task.
        Only completion of the vcs-clustered-service task
        will result in a change of state of that model item"
        """
        vips = service.query("vip")
        file_systems = service.query("file-system")
        ha_configs = service.query("ha-config-base")
        apps = service.query("service")
        for item in vips + file_systems + ha_configs + apps:
            task.model_items.add(item)
        return task

    @staticmethod
    def get_parent_with_type(item, item_type_id):
        while item:
            if item.item_type.item_type_id == item_type_id:
                return item
            item = item.parent
        return None


def quote(word):
    """ Add double quotes before and after word if neccessary """
    if not word.startswith('"'):
        word = '"' + word
    if not word.endswith('"'):
        word = word + '"'
    return word


def text_join(args, sep=', ', last=' and '):
    """ Add separator between args and last before last arg in list """
    if len(args) < 2:
        return sep.join(args)
    return sep.join(args[:-1]) + last + args[-1]


def format_list(errors):
    """
    Returns a string of correctly formatted errors, sorted alphabetically
    :param: errors (list of strings)
    :return: formatted_errors (str)
    """
    errors = [quote(error) for error in sorted(errors)]
    return text_join(errors)


def get_ip_prefixlen(address):
    """
    Return the prefix length of `address` or None if not defined.
    """
    if '/' in address:
        return address.split('/')[1]
    else:
        return None


def ipv6_prefixlen(address):
    """
    Return the prefix length of `address`. If the address does not contain
    a prefixlen return the default value '64'.
    """
    prefixlen = get_ip_prefixlen(address)
    if not prefixlen:
        prefixlen = DEFAULT_IPV6_PREFIXLEN
    return prefixlen


def strip_prefixlen(address):
    """
    Strip the prefixlen from an ipv6 address.
    """
    return address.split('/', 1)[0]


def is_ipv4(address):
    """
    Return `True` if `address` is a valid ipv4 address otherwise `False`.
    """
    return netaddr.valid_ipv4(address)


def is_ipv6(address):
    """
    Return `True` if `address` is a valid ipv6 address otherwise `False`.
    """
    return netaddr.valid_ipv6(strip_prefixlen(address))


def select_nodes_from_service(service):
    cluster = service.get_cluster()
    if is_os_reinstall_on_peer_nodes(cluster):
        return [node.hostname for node in service.nodes
                if not node.is_for_removal()]
    else:
        return [node.hostname for node in service.nodes
                if not node.is_for_removal() and not node.is_initial()]


def select_nodes_from_cluster(cluster):
    if is_os_reinstall_on_peer_nodes(cluster):
        return [node.hostname for node in cluster.nodes
                if not node.is_for_removal()]
    else:
        return [node.hostname for node in cluster.nodes
                if not node.is_for_removal() and not node.is_initial()]


def is_os_reinstall_on_peer_nodes(cluster):
    return any([True for node in cluster.nodes
                for upgrd_item in node.query('upgrade')
                if hasattr(upgrd_item, 'os_reinstall')
                and upgrd_item.os_reinstall == 'true'])


def is_pre_os_reinstall_on_peer_nodes(cluster):
    if not cluster.is_initial() and is_os_reinstall_on_peer_nodes(cluster):
        return True


def is_ha_manager_only_on_nodes(api):
    if api and any([True for node in api.query('node')
                    for upgrd_item in node.query('upgrade')
                    if hasattr(upgrd_item, 'ha_manager_only')
                    and upgrd_item.ha_manager_only == 'true']):
        return True
    return False


def get_subnet_netmask(subnet):
    """
    Get the netmask from a subnet a valid subnet. None otherwise.
    """
    if subnet:
        return str(netaddr.IPNetwork(subnet).netmask)
