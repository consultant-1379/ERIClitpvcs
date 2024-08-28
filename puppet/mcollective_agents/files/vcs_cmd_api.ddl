metadata    :name        => "vcs_cmd_api",
            :description => "API to access VCS cli commands via mco",
            :author      => "Ericsson AB",
            :license     => "Ericsson",
            :version     => "1.0",
            :url         => "http://ericsson.com",
            :timeout     => 1000

action "haconf", :description => "access haconf command" do
    display :always

    input  :haaction,
           :prompt      => "action",
           :description => "makerw or dump",
           :type        => :list,
           :optional    => false,
           :list        => ["makerw", "dump"]

    input  :read_only,
           :prompt      => "read_only",
           :description => "make db read only, used for dump option",
           :type        => :boolean,
           :optional    => true

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "probes_pending", :description => "Are there probes pending on this system" do
    display :always

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"
end

action "hagrp_add", :description => "access hagrp -add command" do
    display :always

    input  :group_name,
           :prompt      => "Group Name",
           :description => "The name of the group",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "hagrp_remove", :description => "access hagrp -delete command" do
    display :always

    input  :group_name,
           :prompt      => "Group Name",
           :description => "The name of the group",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "hagrp_list", :description => "access hagrp -list command" do
    display :always

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "hagrp_remove_resources", :description => "remove all resources belonging to a group" do
    display :always

    input  :group_name,
           :prompt      => "Group Name",
           :description => "The name of the group",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "hagrp_offline", :description => "access hagrp -add command" do
    display :always

    input  :group_name,
           :prompt      => "Group Name",
           :description => "The name of the group",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    input  :system,
           :prompt      => "System to offline",
           :description => "The name of the system to offline",
           :type        => :string,
           :validation  => '',
           :optional    => true,
           :maxlength   => 0

    input  :force,
           :prompt      => "force",
           :description => "delete with -force option",
           :type        => :boolean,
           :optional    => true

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "hagrp_link", :description => "access hagrp -link command" do
    display :always

    input  :parent,
           :prompt      => "Parent group in the dependency",
           :description => "The name of the parent group",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    input  :child,
           :prompt      => "Child group in the dependency",
           :description => "The name of the child group",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    input  :gd_category,
           :prompt      => "category of the group dependency",
           :description => "online or offline",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    input  :gd_location,
           :prompt      => "location of the group dependency",
           :description => "local or remote",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    input  :gd_type,
           :prompt      => "type of the group dependency",
           :description => "firm or soft",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "hagrp_unlink", :description => "access hagrp -unlink command" do
    display :always

    input  :parent,
           :prompt      => "Parent group in the dependency",
           :description => "The name of the parent group",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    input  :child,
           :prompt      => "Child group in the dependency",
           :description => "The name of the child group",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "hastatus", :description => "access hastatus -sum command" do
    display :always

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "hagrp_delete_in_system_list", :description => "access hagrp - hagrp_delete_in_system_list command" do
    display :always

    input  :group_name,
           :prompt      => "Group Name",
           :description => "The name of the group",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    input  :attribute_val,
           :prompt      => "Attribute Value",
           :description => "The value of the attribute",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    input  :force,
           :prompt      => "force",
           :description => "delete with -force option",
           :type        => :boolean,
           :optional    => true

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "hagrp_add_in_system_list", :description => "access hagrp -hagrp_add_in_system_list command" do
    display :always

    input  :group_name,
           :prompt      => "Group Name",
           :description => "The name of the group",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    input  :attribute_val,
           :prompt      => "Attribute Value",
           :description => "The value of the attribute",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "hagrp_add_in_auto_start_list", :description => "access hagrp -hagrp_add_in_auto_start_list command" do
    display :always

    input  :group_name,
           :prompt      => "Group Name",
           :description => "The name of the group",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    input  :attribute_val,
           :prompt      => "Attribute Value",
           :description => "The value of the attribute",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "hagrp_add_in_triggers_enabled", :description => "access hagrp -hagrp_add_in_triggers_enabled command" do
    display :always

    input  :group_name,
           :prompt      => "Group Name",
           :description => "The name of the group",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    input  :attribute_val,
           :prompt      => "Attribute Value",
           :description => "The value of the attribute",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "hagrp_delete_in_triggers_enabled", :description => "access hagrp -hagrp_delete_in_triggers_enabled command" do
    display :always

    input  :group_name,
           :prompt      => "Group Name",
           :description => "The name of the group",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    input  :attribute_val,
           :prompt      => "Attribute Value",
           :description => "The value of the attribute",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "hagrp_modify", :description => "access hagrp -modify command" do
    display :always

    input  :group_name,
           :prompt      => "Group Name",
           :description => "The name of the group",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    input  :attribute,
           :prompt      => "Attribute Name",
           :description => "The name of the attribute",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    input  :attribute_val,
           :prompt      => "Attribute Value",
           :description => "The value of the attribute",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "hagrp_check_states", :description => "Checks group is online" do
    display :always

    input  :group_name,
           :prompt      => "Group Name",
           :description => "The name of the group",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    input  :node_name,
           :prompt      => "Node Name",
           :description => "The name of the node",
           :type        => :string,
           :validation  => '',
           :optional    => true,
           :maxlength   => 0

    input  :state,
           :prompt      => "State",
           :description => "State to wait for",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :default     => "ONLINE",
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "hagrp_wait", :description => "Checks group is online" do
    display :always

    input  :group_name,
           :prompt      => "Group Name",
           :description => "The name of the group",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    input  :node_name,
           :prompt      => "Node Name",
           :description => "The name of the node",
           :type        => :string,
           :validation  => '',
           :optional    => true,
           :maxlength   => 0

    input  :timeout,
           :prompt      => "Timeout",
           :description => "Timeout for the wait command",
           :type        => :integer,
           :optional    => false,
           :maxlength   => 0

    input  :state,
           :prompt      => "State",
           :description => "State to wait for",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :default     => "ONLINE",
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "hagrp_online", :description => "Brings group online" do
    display :always

    input  :group_name,
           :prompt      => "Group Name",
           :description => "The name of the group",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0


    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "hagrp_value", :description => "Return value of an attribute on a group" do
    display :always

    input  :group_name,
           :prompt      => "Group Name",
           :description => "The name of the group",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    input  :attribute,
           :prompt      => "Attribute Name",
           :description => "The attribute of the group",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    input  :system,
           :prompt      => "system",
           :description => "The name of the system",
           :type        => :string,
           :validation  => '',
           :optional    => true,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "hares_add", :description => "access hares -add command" do
    display :always

    input  :resource,
           :prompt      => "Resource Name",
           :description => "The name of the resource",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    input  :type,
           :prompt      => "Resource Type",
           :description => "The type of the resource",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    input  :group_name,
           :prompt      => "Group Name",
           :description => "The name of the group",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end


action "hares_delete", :description => "access hares -delete command" do
    display :always

    input  :resource,
           :prompt      => "Resource Name",
           :description => "The name of the resource",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "hares_modify", :description => "access hares -modify command" do
    display :always

    input  :resource,
           :prompt      => "Resource Name",
           :description => "The name of the resource",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    input  :attribute,
           :prompt      => "Attribute Name",
           :description => "The name of the attribute",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    input  :attribute_val,
           :prompt      => "Attribute Value",
           :description => "The value of the attribute",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    input  :sys,
           :prompt      => "System",
           :description => "The system to apply the attribute to",
           :type        => :string,
           :validation  => '',
           :optional    => true,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "hares_local", :description => "access hares -local command" do
    display :always

    input  :resource,
           :prompt      => "Resource Name",
           :description => "The name of the resource",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    input  :attribute,
           :prompt      => "Attribute Name",
           :description => "The name of the attribute",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "hares_override_attribute", :description => "access hares -override command" do
    display :always

    input  :resource,
           :prompt      => "Resource Name",
           :description => "The name of the resource",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    input  :attribute,
           :prompt      => "Attribute Name",
           :description => "The name of the attribute",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "hares_link", :description => "access hares -link command" do
    display :always

    input  :parent,
           :prompt      => "Parent Resource Name",
           :description => "The name of the parent resource",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    input  :child,
           :prompt      => "Child Resource Name",
           :description => "The name of the child resource",
           :type        => :string,
           :validation  => '',
           :optional    => true,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"
end

action "hares_unlink", :description => "access hares -unlink command" do
    display :always

    input  :parent,
           :prompt      => "Parent Resource Name",
           :description => "The name of the parent resource",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    input  :child,
           :prompt      => "Child Resource Name",
           :description => "The name of the child resource",
           :type        => :string,
           :validation  => '',
           :optional    => true,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"
end

action "hares_probe", :description => "access hares -probe command" do
    display :always

    input  :resource,
           :prompt      => "Resource Name",
           :description => "The name of the resource",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    input  :sys,
           :prompt      => "System",
           :description => "The system to be probed",
           :type        => :string,
           :validation  => '',
           :optional    => true,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "hacf_verify", :description => "Verify man.cf is correct" do
    display :always

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "haclus_ro", :description => "Checks main.cf is readonly" do
    display :always

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "hagrp_resources", :description => "Gets the group resources" do
    display :always

    input  :group_name,
           :prompt      => "Group Name",
           :description => "The name of the group",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0


    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "get_group_state", :description => "Gets the group state" do
    display :always

    input  :group_name,
           :prompt      => "Group Name",
           :description => "The name of the group",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    input  :active_count,
           :prompt      => "Number of expected online nodes",
           :description => "The number of nodes the group should be active on",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    input  :offline_count,
           :prompt      => "Number of expected offline nodes",
           :description => "The number of nodes the group should not be active on",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The state of the group",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "get_group_state_on_nodes", :description => "Gets the group state on a particular node" do
    display :always

    input  :group_name,
           :prompt      => "Group Name",
           :description => "The name of the group",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The state of the group",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "hares_list", :description => "Lists all VCS resources" do
    display :always

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "hasys_freeze", :description => "Locks a node" do
    display :always

    input  :node,
           :prompt      => "Node Name",
           :description => "The name of the node",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "lock", :description => "Locks a node" do
    display :always

    input  :sys,
           :prompt      => "Node Name",
           :description => "The name of the node",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    input  :switch_timeout,
           :prompt      => "Failover groups switch timeout",
           :description => "The time to wait for the failover groups to offline during switch",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    input  :prevent_failover_grps,
           :prompt      => "Groups which should not be failed over",
           :description => "",
           :type        => :string,
           :validation  => '',
           :optional    => true,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end


action "unlock", :description => "Unlocks a node" do
    display :always

    input  :sys,
           :prompt      => "Node Name",
           :description => "The name of the node",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    input  :nic_wait_timeout,
           :prompt      => "NIC SG timeout",
           :description => "The time to wait for the NICs to be up",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    input  :prevent_failover_grps,
           :prompt      => "Groups which should not be failed over",
           :description => "",
           :type        => :string,
           :validation  => '',
           :optional    => true,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "cluster_ready", :description => "Unlocks a node" do
    display :always

    input  :systems,
           :prompt      => "VCS nodes",
           :description => "Coma separated list of nodes in VCS cluster",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end


action "cluster_stopped", :description => "Tests if cluster is stopped" do
    display :always

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end


action "check_evacuated", :description => "Checks if a node has been evaucated" do
    display :always

    input  :sys,
           :prompt      => "Node Name",
           :description => "The name of the node",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "cluster_app_agent_num_threads", :description => "Set the number of threads the VCS application agent uses to manage application resources" do
    display :always

    input  :app_agent_num_threads,
           :prompt      => "Application NumThreads value",
           :description => "The number of threads the VCS application agent uses to manage application resources.",
           :type        => :integer,
           :optional    => false,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "check_cluster_online", :description => "Checks if a cluster is brought online" do
    display :always

    input  :sys,
           :prompt      => "Node Name",
           :description => "The name of the node",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    input  :prevent_failover_grps,
           :prompt      => "Groups which should not be failed over",
           :description => "",
           :type        => :string,
           :validation  => '',
           :optional    => true,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "probe_all_nics", :description => "Probe all NIC resources" do
    display :always

    input  :sys,
           :prompt      => "Node Name",
           :description => "The node hostname",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "hasys_unfreeze", :description => "Locks a node" do
    display :always

    input  :node,
           :prompt      => "Node Name",
           :description => "The name of the node",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "hasys_delete", :description => "Removes a node from vcs" do
    display :always

    input  :node,
           :prompt      => "Node Name",
           :description => "The name of the node",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "hasys_state", :description => "Get state of a node" do
    display :always

    input  :node,
           :prompt      => "Node Name",
           :description => "The name of the node",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "start_vx_fencing", :description => "Starts Vx Fencing" do
    display :always

    input  :sys,
           :prompt      => "System",
           :description => "The system to run the command on",
           :type        => :string,
           :validation  => '',
           :optional    => true,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "stop_vx_fencing", :description => "Stops Vx Fencing" do
    display :always

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "stop_vcs", :description => "Stops VCS" do
    display :always

    input  :force,
           :prompt      => "Force",
           :description => "Leave resources up and running",
           :type        => :string,
           :validation  => '',
           :optional    => true,
           :maxlength   => 0

    input  :sys,
           :prompt      => "System",
           :description => "The system to run the command on",
           :type        => :string,
           :validation  => '',
           :optional    => true,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "start_vcs", :description => "Starts VCS" do
    display :always

    input  :sys,
           :prompt      => "System",
           :description => "The system to run the command on",
           :type        => :string,
           :validation  => '',
           :optional    => true,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "vxfen_admin", :description => "Runs command for VX Fencing admin" do
    display :always

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "vxfen_config", :description => "Runs command for VX Fencing config" do
    display :always

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "edit_maincf_use_fence", :description => "Runs main.cf edit command to UseFence=SCSI3" do
    display :always

    input  :cluster_name,
           :prompt      => "Cluster Name",
           :description => "The cluster name that appears near the top of main.cf",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "get_dg_hostname", :description => "Check where DG is available" do
    display :always

    input :dg_name,
          :prompt      => "dg_name",
          :description => "Disk group name",
          :type        => :string,
          :validation  => '',
          :optional    => false,
          :maxlength   => 300

    output :status,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"
end

action "deport_disk_group", :description => "Deport a disk group" do
    display :always

    input :dg_name,
          :prompt      => "Disk Group Name",
          :description => "The name of the Disk Group",
          :type        => :string,
          :validation  => '',
          :optional    => false,
          :maxlength   => 300

    output :status,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"
end

action "hagrp_unlink_all", :description => "Removes all group's dependencies." do
    display :always

    input  :group,
           :prompt      => "Service group",
           :description => "Service group",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"
end

action "hares_unlink_pattern", :description => "Removes resource's dependencies that match with the given pattern." do
    display :always

    input  :resource,
           :prompt      => "Resource name",
           :description => "Resource name",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    input  :pattern,
           :prompt      => "Pattern",
           :description => "String containing the pattern to be used for matching",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"
end

action "ensure_ipv6_nodad", :description => "sets nodad option on IPv6 IP resource for haproxy." do
    display :always

    input  :group_name,
           :prompt      => "Group Name",
           :description => "The name of the group",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"
end

action "api_update_ip_resources_of_a_network", :description => "Update IP resources belonging to a network" do
    display :always

    input  :data_json,
           :prompt      => "JSON formatted data",
           :description => "JSON formatted with list of updated IP Resource data, mapped by IP Resource Name Prefix",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"
end

action "flush_resource", :description => "Executes hares -flushinfo resources in Stale state" do
    display :always

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"
end

action "remove_standby_node", :description => "Changes the standby node on a failover service" do
    display :always

    input  :group_name,
           :prompt      => "Group Name",
           :description => "Name of failover service group",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    input  :removed_node,
           :prompt      => "Retained Node",
           :description => "Name of node being removed in the group",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    input  :new_node,
           :prompt      => "Retained Node",
           :description => "Name of node being new in the group",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"
end

action "add_standby_node", :description => "Changes ..." do
    display :always

    input  :group_name,
           :prompt      => "Group Name",
           :description => "Name of failover service group",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    input  :new_node,
           :prompt      => "Retained Node",
           :description => "Name of node being new in the group",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"
end

action "check_ok_to_online", :description => "Checks if group OK to online on a node" do
    display :always

    input  :group,
           :prompt      => "Group name",
           :description => "The name of the group",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    input  :node,
           :prompt      => "Node name",
           :description => "the node on which group should be checked",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "hagrp_switch_to_node", :description => "switch service to given node" do
    display :always

    input  :group_name,
           :prompt      => "Group Name",
           :description => "The name of the group",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    input  :node,
           :prompt      => "Node Name",
           :description => "The name of the node",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "get_etc_llthosts", :description => "Get the contents of /etc/llthosts" do
    display :always

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The content of /etc/llthosts",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end
