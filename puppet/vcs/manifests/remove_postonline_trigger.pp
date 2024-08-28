define vcs::remove_postonline_trigger ( ) {
  file { 'postonline':
    path    => '/opt/VRTSvcs/bin/triggers/postonline',
    ensure  => absent,
  }
}

