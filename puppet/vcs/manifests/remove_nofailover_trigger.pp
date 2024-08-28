define vcs::remove_nofailover_trigger ( ) {
  file { 'nofailover':
    path    => '/opt/VRTSvcs/bin/triggers/nofailover',
    ensure  => absent,
  }
}

