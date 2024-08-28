define vcs::configure_nofailover_trigger (
            $trigger_map,
            ) {
  file { 'nofailover':
    path    => '/opt/VRTSvcs/bin/triggers/nofailover',
    ensure  => file,
    mode    => '0755',
    content => template('vcs/nofailover.erb'),
  }
}

