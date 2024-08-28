# Define the VCS configuration
define vcs::configure (
            $cluster_name,               # string
            $license_key,                # string
            $cluster_ID,                 # int
            $clust_type,                 # string
            $cluster_UUID,               # string
            $number_of_nodes,            # int
            $hostname,                   # string
            $hostnames,                  # hash table
            $heartbeats_MACs,            # hash table
            $managment_MAC,              # hash table
            $rpm_list,                   # list
            $fencing_dg_name = 'None',   # string
            $manage_vxfencing = 'false', # string
            $base_os = '',               # string
            $heartbeats_SAPs = {},       # hash table
            $management_SAP = {},        # hash table
            $boot_mode = 'bios'          # string
            ) {

  Exec { path => [ '/bin/', '/sbin/' , '/usr/bin/', '/usr/sbin/' ] }

  if $base_os == 'rhel6' {
      $start_vxfen_cmd = '/sbin/service vxfen start'
      $start_llt_cmd   = '/sbin/service llt start'
      $stop_llt_cmd    = '/sbin/service llt stop'
      $status_vcs_cmd  = '/etc/init.d/vcs status'
  }
  else {
      $service_cmd = '/usr/bin/systemctl'
      $start_vxfen_cmd = "${service_cmd} start vxfen"
      $start_llt_cmd   = "${service_cmd} start llt"
      $stop_llt_cmd    = "${service_cmd} stop llt"
      $status_vcs_cmd  = "${service_cmd} status vcs.service"
  }

# LITPCDS-4176: 'exec' fo yum install instead of 'package':
  exec { 'install-rpms':
    command => "yum install -y ${rpm_list}",
    unless  => "rpm -q ${rpm_list}",
    timeout => 0,
    require => [Yumrepo['3PP'], File['maincf']],
  }

# The license for Veritas have to be set up first
  exec { 'vxkeyless':
    command => "/opt/VRTSvlic/bin/vxkeyless set -q ${license_key}",
    require => Exec ['install-rpms'],
    unless  => ["test '${::vx_license_exists}' = 'true'",
                "/opt/VRTSvlic/bin/vxkeyless display -v|grep '${license_key}'"],
  }

# After license is set up then LLT links have to be configured
  file { 'llthosts':
    ensure  => file,
    path    => '/etc/llthosts',
    content => template('vcs/llthosts.erb'),
  }

  file { 'llttab':
    ensure  => file,
    path    => '/etc/llttab',
    content => template('vcs/llttab.erb'),
  }

  service { 'llt':
    ensure    => 'running',
    name      => 'llt',
    enable    => true,
    start     => "${start_llt_cmd} 2>&1 | logger -t\
                  llt-service ; exit \${PIPESTATUS[0]}",
    stop      => "${stop_llt_cmd} 2>&1 | logger -t\
                  llt-service ; exit \${PIPESTATUS[0]}",
    status    => '/sbin/lltconfig',
    require   => [File['llthosts'], File['llttab'], Exec['vxkeyless']],
    hasstatus => false,
  }

  # Note that the 'unless' command in the execs 'check_service_llt',
  # 'check_service_gab'and 'check_service_vcs' is used to avoid the exec
  # command being shown in the log on every puppet run. The exec is only run
  # if the unless fails
  exec { 'check_service_llt':
    command => "${start_llt_cmd} 2>&1 | logger -t llt-service &&\
                /sbin/lltconfig | grep 'is running'",
    unless  => "/sbin/lltconfig | grep 'is running'",
    timeout => 0,
    require => [Service['llt']],
  }

  exec { 'disable_llt_heartbeat':
    command => '/sbin/lltconfig -H hbthread:0',
    unless  =>  "lltconfig -H query | grep 'hbthread.*=.*0'",
    timeout => 0,
    require => [Service['llt']],
  }

  # When LLT links are in place we cen set up GAB
  file { 'gabtab':
    ensure  => file,
    path    => '/etc/gabtab',
    content => template('vcs/gabtab.erb'),
  }

  file { 'gab':
    ensure => file,
    path   => '/etc/sysconfig/gab',
    mode   => '0754',
    source => 'puppet:///modules/vcs/gab',
  }

  service { 'gab':
    ensure    => 'running',
    name      => 'gab',
    enable    => true,
    status    => '/sbin/gabconfig -a',
    require   => [File['gabtab'], File['gab'], Exec['check_service_llt']],
    hasstatus => false,
  }

  # This is necessary as VCS does not reload /etc/gabtab file
  # once it is changed. It's rather to keep the runtime in sync
  # to the configuration, as it should not have any impact on
  # cluster activity.
  exec { 'set_vcs_seed_threshold':
    command => "/sbin/gabconfig -c -n${number_of_nodes}",
    unless  => "/sbin/gabconfig -l | grep -E 'Node count[^0-9]+${number_of_nodes}'",
    timeout => 0,
    require => [Service['gab']],
  }

  exec { 'check_service_gab':
    command => '/sbin/gabconfig -a',
    unless  => '/sbin/gabconfig -a',
    timeout => 0,
    require => [Service['gab']],
  }

  # Finally we provide basic configuration for cluster in main.cf
  #   then we start VCS service on all nodes
  # Note:We will not replace main.cf file if it's change by VCS itself
  #or by some configuration commands. We will just provide initial
  #configuration.
  #This is done by replace = 'no' configuration option
  # create a directory structure for main.cf
  $path_for_main_cf = ['/etc/VRTSvcs/', '/etc/VRTSvcs/conf/',
                      '/etc/VRTSvcs/conf/config/']

  file { $path_for_main_cf:
    ensure => 'directory',
    mode   => '0755',
  }

  file { 'maincf':
    ensure  => file,
    path    => '/etc/VRTSvcs/conf/config/main.cf',
    replace => 'no',
    require => File [$path_for_main_cf],
    content => template('vcs/main.cf.erb'),
  }

  file { '/etc/vx/.uuids':
    ensure  => directory,
    require => Exec ['install-rpms'],
  }

  file { 'clusuuid':
    ensure  => file,
    path    => '/etc/vx/.uuids/clusuuid',
    content => template('vcs/clusuuid.erb'),
    notify  => Service['vcs'],
    require => Exec ['install-rpms'],
  }

  file { 'vcs':
    ensure  => file,
    path    => '/etc/sysconfig/vcs',
    mode    => '0600',
    source  => 'puppet:///modules/vcs/vcs',
    require => Exec ['install-rpms'],
  }

  service { 'vcs':
    ensure  => 'running',
    name    => 'vcs',
    enable  => true,
    require => [File['maincf'], File['clusuuid'], File['vcs'],
                Exec['check_service_gab']],
  }

  exec { 'check_service_vcs':
    command => $status_vcs_cmd,
    unless  => $status_vcs_cmd,
    timeout => 0,
    require => [Service['vcs']],
  }

  file { 'vcs_path':
    ensure  => file,
    path    => '/etc/profile.d/vcs_path.sh',
    mode    => '0600',
    content => 'export PATH=$PATH:/opt/VRTSvcs/bin:/opt/VRTS/bin'
  }

  file { 'vcs_lsb_start_wrapper':
    ensure  => file,
    require => File['litp_vcs_wrapper_dir'],
    path    => '/usr/share/litp/vcs_lsb_start',
    mode    => '0755',
    source  => 'puppet:///modules/vcs/vcs_lsb_start',
  }

  file { 'vcs_lsb_stop_wrapper':
    ensure  => file,
    require => File['litp_vcs_wrapper_dir'],
    path    => '/usr/share/litp/vcs_lsb_stop',
    mode    => '0755',
    source  => 'puppet:///modules/vcs/vcs_lsb_stop',
  }

  file { 'vcs_lsb_status_wrapper':
    ensure  => file,
    require => File['litp_vcs_wrapper_dir'],
    path    => '/usr/share/litp/vcs_lsb_status',
    mode    => '0755',
    source  => 'puppet:///modules/vcs/vcs_lsb_status',
  }

    file { 'vcs_lsb_vm_status_wrapper':
    ensure  => file,
    require => File['litp_vcs_wrapper_dir'],
    path    => '/usr/share/litp/vcs_lsb_vm_status',
    mode    => '0755',
    source  => 'puppet:///modules/vcs/vcs_lsb_vm_status',
  }

  file { 'vcs_nasend_wrapper':
    ensure  => file,
    require => File['litp_vcs_wrapper_dir'],
    path    => '/usr/share/litp/nasend.py',
    mode    => '0755',
    source  => 'puppet:///modules/vcs/nasend.py',
  }

  file { 'litp_vcs_wrapper_dir':
    ensure => directory,
    path   => '/usr/share/litp',
    mode   => '0755',
    owner  => 'root',
    group  => 'root',
  }

  # LITPCDS-11414: Add a script to disable the VCS low priority interface
  # before shutdown. It happens after vcs is stopped but before llt is stopped
  file { 'shutdown_llt_lowpri':
    ensure => file,
    path   => '/etc/init.d/shutdown_llt_lowpri',
    mode   => '0755',
    source => 'puppet:///modules/vcs/shutdown_llt_lowpri',
  }

  exec { 'shutdown_llt_lowpri_updated':
      command     => 'service shutdown_llt_lowpri start &&\
                      /sbin/chkconfig --add shutdown_llt_lowpri',
      timeout     => 0,
      subscribe   => File['shutdown_llt_lowpri'],
      refreshonly => true
  }

  # ## I/O Fencing ##
  # only performed if I/O fencing is required
  if $fencing_dg_name != 'None' {

    file { 'vxfendg':
      ensure  => file,
      path    => '/etc/vxfendg',
      require => Exec ['install-rpms'],
      content => template('vcs/vxfendg.erb'),
    }

    file { 'vxfenmode':
      ensure  => file,
      path    => '/etc/vxfenmode',
      require => Exec ['install-rpms'],
      content => template('vcs/vxfenmode.erb'),
    }
  }

  ## Workaround for TORF-114106 (3PP world writeable files): #1
  file { 'vx_dir_perm':
    ensure => directory,
    path   => '/var/vx',
    mode   => '0755',
    owner  => 'root',
    group  => 'root',
  }
  file { 'vftrk_dir_perm':
    ensure => directory,
    path   => '/var/vx/vftrk',
    mode   => '0770',
    owner  => 'root',
    group  => 'root',
  }
  file { 'vftrk_vcs_perm':
    ensure => file,
    path   => '/var/vx/vftrk/vcs',
    mode   => '0660',
    owner  => 'root',
    group  => 'root',
  }

  if $clust_type == 'sfha'  {
    ## Workaround for TORF-114106 (3PP world writeable files): #2
    file { 'vftrk_vxfs_perm':
      ensure => file,
      path   => '/var/vx/vftrk/vxfs',
      mode   => '0660',
      owner  => 'root',
      group  => 'root',
    }
    file { 'vftrk_vxvm_perm':
      ensure => file,
      path   => '/var/vx/vftrk/vxvm',
      mode   => '0660',
      owner  => 'root',
      group  => 'root',
    }
    # If the plugin has asked Puppet to manage vxfencing, add the vxfen service
    if $manage_vxfencing == 'true' {
      service { 'vxfen':
        ensure  => 'running',
        name    => 'vxfen',
        enable  => true,
        require => [File['maincf'], File['vcs'], File['clusuuid'],
                    Exec['check_service_gab']],
      }

      # Check that vxfen is running, else try to start it. Sleep for 20 seconds
      # as it can take time for fencing to go to 'running' state
      exec { 'check_service_vxfen':
        command => "${start_vxfen_cmd} 2>&1 | logger -t vxfen-service &&\
                    sleep 20 && /opt/VRTSvcs/vxfen/bin/vxfen status | grep 'running'",
        unless  => "/opt/VRTSvcs/vxfen/bin/vxfen status | grep 'running'",
        timeout => 0,
        require => [Service['vxfen']],
        before  => [Service['vcs']],
      }
    }
  }
}
