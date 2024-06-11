#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2022-2023 Hewlett Packard Enterprise, Inc. All rights reserved.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.system_firmware_utils import CrayRedfishUtils
#from ansible_collections.community.general.plugins.module_utils.cray_redfish_utils import CrayRedfishUtils
from ansible.module_utils.common.text.converters import to_native

# More will be added as module features are expanded
category_commands = {
    "GetInventory": ["GetSystemFWInventory"],
}

def main():
    result = {}
    return_values = {}
    module = AnsibleModule(
        argument_spec=dict(
            category=dict(required=True),
            command=dict(required=True, type='list', elements='str'),
            baseuri=dict(required=True),
            username=dict(),
            password=dict(no_log=True),
            auth_token=dict(no_log=True),
            session_uri=dict(),
            timeout=dict(type='int', default=600),
            resource_id=dict(type='list',elements='str',default=[],required=False),
            update_handle=dict(),
            output_file_name=dict(type='str', default=''),
        ),
        supports_check_mode=False
    )

    category = module.params['category']
    command_list = module.params['command']

    # admin credentials used for authentication
    creds = {'user': module.params['username'],
             'pswd': module.params['password'],
             'token': module.params['auth_token']}


    timeout = module.params['timeout']
    # Build root URI
    root_uri = "https://" + module.params['baseuri']
    #update_uri = "/redfish/v1/UpdateService"
    rf_utils = CrayRedfishUtils(creds, root_uri, timeout, module, data_modification=True)

    # Check that Category is valid
    if category not in category_commands:
        module.fail_json(msg=to_native("Invalid Category '%s'. Valid Categories = %s" % (category, list(category_commands.keys()))))

    # Check that all commands are valid
    for cmd in command_list:
        # Fail if even one command given is invalid
        if cmd not in category_commands[category]:
            module.fail_json(msg=to_native("Invalid Command '%s'. Valid Commands = %s" % (cmd, category_commands[category])))


    if category == "GetInventory":
        for command in command_list:
            if command=="GetSystemFWInventory":
                result = rf_utils.get_sys_fw_inventory({
                      'baseuri': module.params['baseuri'],
                      'username': module.params['username'],
                      'password': module.params['password'],
                      'output_file_name': module.params['output_file_name'],
                      })
                if result['ret']:
                    msg = result.get('msg', False)
                    module.exit_json(msg=msg)
                else:
                    module.fail_json(msg=to_native(result))
      

if __name__ == '__main__':
    main()