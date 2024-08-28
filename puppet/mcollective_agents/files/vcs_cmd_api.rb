require 'open3'
require 'syslog'

require 'facter'

def log(message)
  # $0 is the current script name
  Syslog.open($0, Syslog::LOG_PID | Syslog::LOG_CONS) { |s| s.err message }
end

def get_system_path
    res = %x[source /etc/profile;  facter path]
    path =  res.split("=>").last
    return path
end

def add_use_fence_maincf(cluster_name)
    filename = "/etc/VRTSvcs/conf/config/main.cf"
    outdata = File.read(filename).gsub("cluster " + cluster_name + " \(\n\t\)", "cluster " + cluster_name + " \(\n\tUseFence = SCSI3\n\t\)")

    File.open(filename, 'w') do |out|
      out << outdata
    end
    return ""
end

def disk_group_host dg_name
    Facter.reset
    disk_groups = Facter.value("vxvm_dg")
    status = "NO"
    if !disk_groups.nil? and disk_groups.include?(dg_name)
        status = "OK"
    end
    status
end

def prepare_python_path_for_apis()
    agent_path = "/opt/mcollective/mcollective/agent"
    if ENV["PYTHONPATH"].nil? then
        ENV["PYTHONPATH"] = agent_path
    elsif ! ENV["PYTHONPATH"].include? agent_path then
        ENV["PYTHONPATH"] += ":" + agent_path
    end
end

# Set PYTHONPATH to make vcs_plugin_api package accessible
prepare_python_path_for_apis()


module MCollective
  module Agent
    class Vcs_cmd_api < RPC::Agent
      action "lock" do
        implemented_by "/opt/mcollective/mcollective/agent/vcs_cmd_api.py"
      end

      action "unlock" do
        implemented_by "/opt/mcollective/mcollective/agent/vcs_cmd_api.py"
      end

      action "check_evacuated" do
        implemented_by "/opt/mcollective/mcollective/agent/vcs_cmd_api.py"
      end

      action "check_cluster_online" do
        implemented_by "/opt/mcollective/mcollective/agent/vcs_cmd_api.py"
      end

      action "cluster_ready" do
        implemented_by "/opt/mcollective/mcollective/agent/vcs_cmd_api.py"
      end

      action "cluster_stopped" do
        implemented_by "/opt/mcollective/mcollective/agent/vcs_cmd_api.py"
      end

      action "cluster_app_agent_num_threads" do
        implemented_by "/opt/mcollective/mcollective/agent/vcs_cmd_api.py"
      end

      action "probe_all_nics" do
        implemented_by "/opt/mcollective/mcollective/agent/vcs_cmd_api.py"
      end

      action "haconf" do
        implemented_by "/opt/mcollective/mcollective/agent/vcs_cmd_api.py"
      end

      action "hagrp_check_states" do
        implemented_by "/opt/mcollective/mcollective/agent/vcs_cmd_api.py"
      end

      action "hagrp_wait" do
        implemented_by "/opt/mcollective/mcollective/agent/vcs_cmd_api.py"
      end

      action "hagrp_unlink_all" do
        implemented_by "/opt/mcollective/mcollective/agent/vcs_cmd_api.py"
      end

      action "hares_unlink_pattern" do
        implemented_by "/opt/mcollective/mcollective/agent/vcs_cmd_api.py"
      end

      action "hagrp_unlink" do
        implemented_by "/opt/mcollective/mcollective/agent/vcs_cmd_api.py"
      end

      action "hares_override_attribute" do
        implemented_by "/opt/mcollective/mcollective/agent/vcs_cmd_api.py"
      end

      action "stop_vcs" do
        implemented_by "/opt/mcollective/mcollective/agent/vcs_cmd_api.py"
      end

      action "probes_pending" do
        # Sums ProbesPending across all Service Groups and returns the result
        cmd = %{ /opt/VRTS/bin/hagrp -list | awk '{ print $1 }' | uniq | xargs -I % hagrp -value % ProbesPending -clus \`haclus -list\` | grep ProbesPending | awk '{print $4}' | paste -sd+ | bc}
        reply[:retcode] = run("#{cmd}",
                 :stdout => :out,
                 :stderr => :err,
                 :chomp => true,
                 :environment => {"PATH" => get_system_path})
      end

      action "hastatus" do
        cmd = %{/opt/VRTS/bin/hastatus -sum }

        reply[:retcode] = run("#{cmd}",
                             :stdout => :out,
                             :stderr => :err,
                             :chomp => true,
                             :environment => {"PATH" => get_system_path})
      end

      action "hagrp_add" do
        group = request[:group_name]

        cmd = %{/opt/VRTS/bin/hagrp -list }

        groups = ""

        run("#{cmd}",
              :stdout => groups,
              :stderr => :err,
              :chomp => true,
              :environment => {"PATH" => get_system_path})

        cmd = %{/opt/VRTS/bin/hagrp -state } + group

        state = ""

        run("#{cmd}",
              :stdout => state,
              :stderr => :err,
              :chomp => true,
              :environment => {"PATH" => get_system_path})
        if state.include?("FAULTED") then
          log("FAULTED group!")
          cmd = %{/opt/VRTS/bin/hagrp -clear } + group
          run("#{cmd}",
              :stdout => state,
              :stderr => :err,
              :chomp => true,
              :environment => {"PATH" => get_system_path})
        end


        if not groups.match(group + '[/\s/]') then
          cmd = %{/opt/VRTS/bin/hagrp -add } + group

          reply[:retcode] = run("#{cmd}",
              :stdout => :out,
              :stderr => :err,
              :chomp => true,
              :environment => {"PATH" => get_system_path})
        else
          reply[:retcode] = 0
        end
      end

      action "hagrp_remove" do
        implemented_by "/opt/mcollective/mcollective/agent/vcs_cmd_api.py"
      end

      action "hagrp_list" do
        implemented_by "/opt/mcollective/mcollective/agent/vcs_cmd_api.py"
      end

      action "hagrp_delete_in_system_list" do
        implemented_by "/opt/mcollective/mcollective/agent/vcs_cmd_api.py"
      end

      action "hagrp_add_in_system_list" do
        implemented_by "/opt/mcollective/mcollective/agent/vcs_cmd_api.py"
      end

      action "hagrp_add_in_auto_start_list" do
        implemented_by "/opt/mcollective/mcollective/agent/vcs_cmd_api.py"
      end

      action "hagrp_add_in_triggers_enabled" do
        implemented_by "/opt/mcollective/mcollective/agent/vcs_cmd_api.py"
      end

      action "hagrp_delete_in_triggers_enabled" do
        implemented_by "/opt/mcollective/mcollective/agent/vcs_cmd_api.py"
      end

      action "hagrp_modify" do
        implemented_by "/opt/mcollective/mcollective/agent/vcs_cmd_api.py"
      end

      action "hagrp_remove_resources" do
        group = request[:group_name]

        cmd = %{for res in $(/opt/VRTS/bin/hagrp -resources #{group}); do /opt/VRTS/bin/hares -delete $res; done; }

        reply[:retcode] = run("#{cmd}",
                             :stdout => :out,
                             :stderr => :err,
                             :chomp => true,
                             :environment => {"PATH" => get_system_path})
      end

      action "get_group_state" do
        implemented_by "/opt/mcollective/mcollective/agent/vcs_cmd_api.py"
      end

      action "get_group_state_on_nodes" do
        implemented_by "/opt/mcollective/mcollective/agent/vcs_cmd_api.py"
      end

      action "hagrp_link" do
        parent = request[:parent]
        child = request[:child]
        gd_category = request[:gd_category]
        gd_location = request[:gd_location]
        gd_type = request[:gd_type]
        cmd = %{/opt/VRTS/bin/hagrp -link #{parent} #{child} #{gd_category} #{gd_location} #{gd_type}}
        reply[:retcode] = run("#{cmd}",
                             :stdout => :out,
                             :stderr => :err,
                             :chomp => true,
                             :environment => {"PATH" => get_system_path})

      end

     action "hagrp_online" do
        implemented_by "/opt/mcollective/mcollective/agent/vcs_cmd_api.py"
     end

     action "hagrp_offline" do
        implemented_by "/opt/mcollective/mcollective/agent/vcs_cmd_api.py"
     end

     action "ensure_ipv6_nodad" do
        implemented_by "/opt/mcollective/mcollective/agent/vcs_cmd_api.py"
     end

     action "api_update_ip_resources_of_a_network" do
        implemented_by "/opt/mcollective/mcollective/agent/vcs_plugin_api/api_ip_resource_update.py"
     end

     action "flush_resource" do
        implemented_by "/opt/mcollective/mcollective/agent/vcs_cmd_api.py"
     end

     action "hagrp_value" do
        group = request[:group_name]
        attribute = request[:attribute]
        cmd = %{/opt/VRTS/bin/hagrp -value #{group} #{attribute}}
        if request[:system]
            cmd += %{ #{request[:system]}}
        end

        reply[:retcode] = run("#{cmd}",
                             :stdout => :out,
                             :stderr => :err,
                             :chomp => true,
                             :environment => {"PATH" => get_system_path})
     end

     action "hares_add" do
        implemented_by "/opt/mcollective/mcollective/agent/vcs_cmd_api.py"
     end

     action "hares_delete" do
        implemented_by "/opt/mcollective/mcollective/agent/vcs_cmd_api.py"
     end

     action "remove_standby_node" do
        implemented_by "/opt/mcollective/mcollective/agent/vcs_cmd_api.py"
     end

     action "add_standby_node" do
        implemented_by "/opt/mcollective/mcollective/agent/vcs_cmd_api.py"
     end

     action "check_ok_to_online" do
        implemented_by "/opt/mcollective/mcollective/agent/vcs_cmd_api.py"
     end

      action "hares_modify" do
        resource = request[:resource]
        attr = request[:attribute]
        value = request[:attribute_val]
        sys = ""
        if request[:sys] then
            sys = request[:sys]
        end

        cmd = %{/opt/VRTS/bin/hares -modify } + resource
        cmd += %{ } + attr

        if request[:delete] then
            cmd += %{ -delete }
        end

        cmd += %{ } + value

        if request[:sys] then
            cmd += %{ -sys } + sys
        end

        reply[:retcode] = run("#{cmd}",
                             :stdout => :out,
                             :stderr => :err,
                             :chomp => true,
                             :environment => {"PATH" => get_system_path})
      end

      action "hares_local" do
        resource = request[:resource]
        attr = request[:attribute]

        cmd = %{/opt/VRTS/bin/hares -local } + resource
        cmd += %{ } + attr

        reply[:retcode] = run("#{cmd}",
                             :stdout => :out,
                             :stderr => :err,
                             :chomp => true,
                             :environment => {"PATH" => get_system_path})
      end

      action "hares_link" do
        parent = request[:parent]
        child = request[:child]

        cmd = %{/opt/VRTS/bin/hares -dep } + parent

        resources = ""

        run("#{cmd}",
             :stdout => resources,
             :stderr => :err,
             :chomp => true,
             :environment => {"PATH" => get_system_path})
        array_res = resources.split("\n")
        present_already = false
        array_res.each { |res|
          if res.include?(parent) and res.include?(child) then
            present_already = true

            end
        }
        if present_already
          reply[:retcode] = 0
        else
          cmd = %{/opt/VRTS/bin/hares -link } + parent
          cmd += %{ } + child

          reply[:retcode] = run("#{cmd}",
                             :stdout => :out,
                             :stderr => :err,
                             :chomp => true,
                             :environment => {"PATH" => get_system_path})
        end

      end

      action "hares_unlink" do
        parent = request[:parent]
        child = request[:child]

        cmd = %{/opt/VRTS/bin/hares -unlink } + parent
        cmd += %{ } + child

        reply[:retcode] = run("#{cmd}",
                             :stdout => :out,
                             :stderr => :err,
                             :chomp => true,
                             :environment => {"PATH" => get_system_path})
      end

      action "hares_probe" do
        resource = request[:resource]
        sys = request[:sys]

        cmd = %{/opt/VRTS/bin/hares -probe } + resource
        cmd += %{ -sys } + sys

        reply[:retcode] = run("#{cmd}",
                             :stdout => :out,
                             :stderr => :err,
                             :chomp => true,
                             :environment => {"PATH" => get_system_path})
      end

      action "hacf_verify" do
        cmd = %{/opt/VRTS/bin/hacf -verify /etc/VRTSvcs/conf/config }
        reply[:retcode] = run("#{cmd}",
                             :stdout => :out,
                             :stderr => :err,
                             :chomp => true,
                             :environment => {"PATH" => get_system_path})
     end

     action "haclus_ro" do
        cmd = %{/opt/VRTS/bin/haclus -value ReadOnly }
        reply[:retcode] = run("#{cmd}",
                             :stdout => :out,
                             :stderr => :err,
                             :chomp => true,
                             :environment => {"PATH" => get_system_path})
     end

     action "hagrp_resources" do
        group = request[:group_name]
        cmd = %{/opt/VRTS/bin/hagrp -resources } + group
        reply[:retcode] = run("#{cmd}",
                             :stdout => :out,
                             :stderr => :err,
                             :chomp => true,
                             :environment => {"PATH" => get_system_path})
     end

     action "hares_list" do
        cmd = %{/opt/VRTS/bin/hares -list }
        reply[:retcode] = run("#{cmd}",
                             :stdout => :out,
                             :stderr => :err,
                             :chomp => true,
                             :environment => {"PATH" => get_system_path})
     end

     action "hasys_freeze" do
        cmd = %{/opt/VRTS/bin/hasys -freeze -persistent -evacuate } + request[:node]
        reply[:retcode] = run("#{cmd}",
                             :stdout => :out,
                             :stderr => :err,
                             :chomp => true,
                             :environment => {"PATH" => get_system_path})
     end

     action "hasys_unfreeze" do
        cmd = %{/opt/VRTS/bin/hasys -unfreeze -persistent } + request[:node]
        reply[:retcode] = run("#{cmd}",
                             :stdout => :out,
                             :stderr => :err,
                             :chomp => true,
                             :environment => {"PATH" => get_system_path})
     end

    action "hasys_state" do
        cmd = %{/opt/VRTS/bin/hasys -state } + request[:node]
        reply[:retcode] = run("#{cmd}",
                             :stdout => :out,
                             :stderr => :err,
                             :chomp => true,
                             :environment => {"PATH" => get_system_path})
     end

     action "hasys_delete" do
        implemented_by "/opt/mcollective/mcollective/agent/vcs_cmd_api.py"
     end

     action "start_vx_fencing" do
        os_ver = Facter.value("operatingsystemmajrelease").to_i
        if(os_ver > 6) then
            cmd = %{/usr/bin/systemctl start vxfen}
        else
            cmd = %{/etc/init.d/vxfen start }
        end
        if request[:sys] then
            cmd += %{ -sys } + request[:sys]
        end
        reply[:retcode] = run("#{cmd}",
                             :stdout => :out,
                             :stderr => :err,
                             :chomp => true,
                             :environment => {"PATH" => get_system_path})
     end

     action "stop_vx_fencing" do
        os_ver = Facter.value("operatingsystemmajrelease").to_i
        if(os_ver > 6) then
           cmd = %{/usr/bin/systemctl stop vxfen }
        else
           cmd = %{/etc/init.d/vxfen stop }
        end
        reply[:retcode] = run("#{cmd}",
                             :stdout => :out,
                             :stderr => :err,
                             :chomp => true,
                             :environment => {"PATH" => get_system_path})
     end

     action "start_vcs" do
        cmd = %{/opt/VRTS/bin/hastart }
        if request[:sys] then
            cmd += %{ -sys } + request[:sys]
        end
        reply[:retcode] = run("#{cmd}",
                             :stdout => :out,
                             :stderr => :err,
                             :chomp => true,
                             :environment => {"PATH" => get_system_path})
     end

     action "vxfen_admin" do
        cmd = %{/opt/VRTS/bin/vxfenadm -d }
        reply[:retcode] = run("#{cmd}",
                             :stdout => :out,
                             :stderr => :err,
                             :chomp => true,
                             :environment => {"PATH" => get_system_path})
     end

     action "vxfen_config" do
        cmd = %{/opt/VRTS/bin/vxfenconfig -l }
        reply[:retcode] = run("#{cmd}",
                             :stdout => :out,
                             :stderr => :err,
                             :chomp => true,
                             :environment => {"PATH" => get_system_path})
     end

     action "edit_maincf_use_fence" do
        cmd = %{/bin/true } + add_use_fence_maincf(request[:cluster_name])
        reply[:retcode] = run("#{cmd}",
                             :stdout => :out,
                             :stderr => :err,
                             :chomp => true,
                             :environment => {"PATH" => get_system_path})
     end

     action "get_dg_hostname" do
        dg_name = request[:dg_name]

        response = disk_group_host(dg_name)

        if response == 'OK'
            reply[:retcode] = 0
            reply[:out] = ""
            reply[:err] = ""
        else
            reply[:retcode] = 1
            reply[:out] = ""
            reply[:err] = "disk group not imported"
        end
     end

     action "deport_disk_group" do
        dg_name = request[:dg_name]

        cmd = "/opt/VRTS/bin/vxdg deport #{dg_name}"

        reply[:retcode] = run("#{cmd}",
          :stdout => :out,
          :stderr => :err,
          :chomp => true)
     end

     action "hagrp_switch_to_node" do
        implemented_by "/opt/mcollective/mcollective/agent/vcs_cmd_api.py"
     end

     action "get_etc_llthosts" do
        the_file = '/etc/llthosts'
        reply[:retcode] = run("[ -f #{the_file} ] && /bin/cat #{the_file}",
                              :stdout => :out,
                              :stderr => :err,
                              :chomp => true,
                              :environment => {"PATH" => get_system_path})
     end
    end
  end
end
