define vcs::configure_postonline_trigger (
# the trigger_map is a list of lists, each containing
# [group_name, service_argument, device_name, ip6_address]
# service_argument is currently unused.
            $trigger_map,
            ) {

  file { 'postonline':
    path    => '/opt/VRTSvcs/bin/triggers/postonline',
    ensure  => file,
    mode    => '0755',
    content => template('vcs/postonline.erb'),
  }
}
