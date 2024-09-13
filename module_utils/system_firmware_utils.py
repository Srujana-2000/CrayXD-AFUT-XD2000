# -*- coding: utf-8 -*-

# Copyright (c) 2022-2023 Hewlett Packard Enterprise, Inc. All rights reserved.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
import os
__metaclass__ = type
#import pandas as pd
import json
import subprocess
import time 
from requests_toolbelt import MultipartEncoder
from ansible_collections.community.general.plugins.module_utils.redfish_utils import RedfishUtils
from ansible.module_utils.urls import open_url, prepare_multipart
from ansible.module_utils.six.moves.urllib.error import URLError, HTTPError
import configparser

supported_models=["XD220V","XD225V","XD295V"]
#supported_models=["HPE CRAY XD220V", "HPE CRAY SC XD220V", "HPE CRAY XD225V","HPE CRAY SC XD225V", "HPE CRAY XD295V","HPE CRAY SC XD295V"]

#to get inventory, update
partial_models={}
#{"HPE CRAY XD220v": "XD220"}
supported_targets={
    "XD220V": ["BMC_Master", "BMC", "BIOS", "MainCPLD", "HDDBPPIC", "PDBPIC", "PDBPIC_BMC"],
    "XD225V": ["BMC_Master", "BMC", "BIOS", "MainCPLD", "HDDBPPIC", "PDBPIC", "PDBPIC_BMC"],
    "XD295V": ["BMC_Master", "BMC", "BIOS", "MainCPLD", "HDDBPPIC", "PDBPIC", "PDBPIC_BMC"],
}

all_targets = ['BMC', 'BIOS', 'MainCPLD', 'PDBPIC', 'HDDBPPIC']
 
reboot = {
    "BIOS": ["AC_PC_redfish"],
    "BIOS2": ["AC_PC_redfish"],
    "MainCPLD": ["AC_PC_ipmi"],
    "HDDBPPIC": ["AC_PC_redfish"],
    "PDBPIC": ["AC_PC_redfish"]
}

routing = {
    "XD220V": "0x34 0xa2 0x00 0x19 0xA9",
    "XD225V": "0x34 0xa2 0x00 0x19 0xA9",
    "XD295V": "0x34 0xa2 0x00 0x19 0xA9",
}


class CrayRedfishUtils(RedfishUtils):
    def post_multi_request(self, uri, headers, payload):
        username, password, basic_auth = self._auth_params(headers)
        try:
            resp = open_url(uri, data=payload, headers=headers, method="POST",
                            url_username=username, url_password=password,
                            force_basic_auth=basic_auth, validate_certs=False,
                            follow_redirects='all',
                            use_proxy=True, timeout=self.timeout)
            resp_headers = dict((k.lower(), v) for (k, v) in resp.info().items())
            return True
        except Exception as e:
            return False

    def get_model(self):
        try:
            response = self.get_request(self.root_uri + "/redfish/v1/Systems/Self")
            if response['ret'] is False:
                return "NA"
        except:
            return "NA"
        model="NA"
        try:
            if 'Model' in response['data']:
                model = response['data'][u'Model'].strip()
        except:
            if 'Model' in response:
                model = response[u'Model'].strip()
            else:
                return "NA"
        if model not in partial_models and "XD" in model:
            split_model_array = model.split() #["HPE", "Cray", "XD665"]
            for dum in split_model_array:
                if "XD" in dum:
                    partial_models[model.upper()]=dum.upper()
        return model
        
    def power_state(self):
        response = self.get_request(self.root_uri + "/redfish/v1/Systems/Self")
        if response['ret'] is False:
            return "NA"
        state='None'
        try:
            if 'PowerState' in response['data']:
                state = response['data'][u'PowerState'].strip()
        except:
            if 'PowerState' in response:
                state = response[u'PowerState'].strip()
        return state
        
    def power_on(self):
        payload = {"ResetType": "On"}
        target_uri = "/redfish/v1/Systems/Self/Actions/ComputerSystem.Reset"
        response1 = self.post_request(self.root_uri + target_uri, payload)
        time.sleep(120)
    
    def power_off(self):
        payload = {"ResetType": "ForceOff"}
        target_uri = "/redfish/v1/Systems/Self/Actions/ComputerSystem.Reset"
        response1 = self.post_request(self.root_uri + target_uri, payload)
        time.sleep(120)

    def target_supported(self,model,target):
        try:
            if target in supported_targets[partial_models[model.upper()]]:
                return True
            return False
        except:
            return False
    
    def get_fw_version(self,target):
        try:
            response = self.get_request(self.root_uri + "/redfish/v1/UpdateService/FirmwareInventory"+"/"+target)
            if response['ret'] is False:
                return "NA"
            try:
                version = response['data']['Version']
                return version
            except:
                version = response['Version']
                return version
        except:
            return "NA"
    
 
    def AC_PC_redfish(self):
        payload = {"ResetType": "ForceRestart"}
        target_uri = "/redfish/v1/Systems/Self/Actions/ComputerSystem.Reset"
        response1 = self.post_request(self.root_uri + target_uri, payload)
        time.sleep(180)
        #target_uri = "/redfish/v1/Chassis/Self/Actions/Chassis.Reset"
        #response2 = self.post_request(self.root_uri + target_uri, payload)
        #time.sleep(180)
        return response1

    def AC_PC_ipmi(self, IP, username, password, routing_value): 
        try:
            command='ipmitool -I lanplus -H '+IP+' -U '+username+' -P '+password+' raw '+ routing_value
            subprocess.run(command, shell=True, check=True, timeout=15)
            time.sleep(180)
            self.power_on()
            return True
        except:
            return False
        
    def check_master_ipmi(self, IP, username, password): 
        try:
            command='ipmitool -I lanplus -H '+IP+' -U '+username+' -P '+password+' raw '+' 0x34 '+' 0xa4 '
            response = subprocess.run(command, shell=True, stdout=subprocess.PIPE,universal_newlines=True)
            response_check = response.stdout
            split = response_check.split()
            node = split[1]
            command='ipmitool -I lanplus -H '+IP+' -U '+username+' -P '+password+' raw '+' 0x34 '+' 0xA6 '+node
            response = subprocess.run(command, shell=True, stdout=subprocess.PIPE,universal_newlines=True)
            response_check = response.stdout
            split = response_check.split()
            master_key = split[0]
            byte_0_int = int(master_key,16)
            byte_0_bin = format(byte_0_int, '08b')
            if byte_0_bin[2]=="1":
                self.power_on()
                return True
            else:
                return False
        except:
            return False
        
    def check_non_master_ipmi(self, IP, username, password): 
        try:
            command='ipmitool -I lanplus -H '+IP+' -U '+username+' -P '+password+' raw '+' 0x34 '+' 0xa4 '
            response = subprocess.run(command, shell=True, stdout=subprocess.PIPE,universal_newlines=True)
            response_check = response.stdout
            split = response_check.split()
            node = split[1]
            command='ipmitool -I lanplus -H '+IP+' -U '+username+' -P '+password+' raw '+' 0x34 '+' 0xa6 '+node
            response = subprocess.run(command,shell=True, stdout=subprocess.PIPE,universal_newlines=True)
            response_check = response.stdout
            split = response_check.split()
            master_key = split[0]
            byte_0_int = int(master_key,16)
            byte_0_bin = format(byte_0_int, '08b')
            if byte_0_bin[2]!="1":
                return True
            else:
                return False
        except:
            return False
        

    def get_sys_fw_inventory(self,attr):
        IP = attr.get('baseuri')
        csv_file_name = attr.get('output_file_name')
        model = self.get_model()
        if not os.path.exists(csv_file_name):      
            f = open(csv_file_name, "w")
            to_write="IP_Address,Model,BMC,BIOS,MainCPLD,PDBPIC,HDDBPPIC\n"
            f.write(to_write)
            f.close()
        entry=[]
        entry.append(IP)
        if model=="NA":
            entry.append("unreachable/unsupported_system") #unreachable or not having model field correctly, i.e not even a XD system
            for target in all_targets:
                entry.append("NA")
        elif partial_models[model.upper()] not in supported_models: #might be a Cray XD like XD685 which is not yet supported
            entry.append("unsupported_model, ")
            for target in all_targets:
                entry.append("NA")
        else:
            entry.append(model)
            for target in all_targets:
                if target in supported_targets[partial_models[model.upper()]]:
                    version=self.get_fw_version(target)
                else:
                    version = "NA"
                entry.append(version)
        new_data=",".join(entry)
        return {'ret': True,'changed': True, 'msg': str(new_data)}

    def helper_update(self,update_status,target,image_path,image_type,IP,username,password,model):
        before_version=None
        after_version=None
        update_status=None
        before_version = self.get_fw_version(target)

        if not before_version.startswith("NA"):
            #proceed for update
            response = self.get_request(self.root_uri + "/redfish/v1/UpdateService")
            if response['ret'] is False:
                update_status="UpdateService api not found"
            else:
                data = response['data']
                if 'MultipartHttpPushUri' in data:
                    headers = {'Expect': 'Continue','Content-Type': 'multipart/form-data'}
                    body = {}
                    targets_uri='/redfish/v1/UpdateService/FirmwareInventory/'+target+'/'
                    body['UpdateParameters'] = (None, json.dumps({"Targets": [targets_uri]}), 'application/json')
                    body['OemParameters'] = (None, json.dumps({"ImageType": image_type}) , 'application/json')
                    with open(image_path, 'rb') as image_path_rb: 
                        body['UpdateFile'] = (image_path, image_path_rb,'application/octet-stream' )
                        encoder = MultipartEncoder(body)
                        body = encoder.to_string()
                        headers['Content-Type'] = encoder.content_type
                        response = self.post_multi_request(self.root_uri + data['MultipartHttpPushUri'],
                                                    headers=headers, payload=body)
                        if response is False:
                            update_status="failed_Post"
                            after_version="NA"
                        else:
                            #add time.sleep (for BMC to comeback after flashing )
                            if target == "BIOS" or target == "BIOS2":
                                time.sleep(300)
                            else:
                                time.sleep(650)
                            #call reboot logic based on target
                            update_status="success"
                            if target in reboot:
                                what_reboots = reboot[target]
                                for reb in what_reboots:
                                    if reb=="AC_PC_redfish":
                                        result=self.AC_PC_redfish()
                                        if not result:
                                            update_status="reboot_failed"
                                            break
                                        time.sleep(600)
                                    elif reb=="AC_PC_ipmi":
                                        result = self.AC_PC_ipmi(IP, username, password, routing[partial_models[model.upper()]]) #based on the model end routing code changes 
                                        if not result:
                                            update_status="reboot_failed"
                                            break 
                            if update_status.lower()=="success":
                                after_version=self.get_fw_version(target)
                            else:
                                after_version="NA"

            return before_version,after_version,update_status
        else:
            after_version="NA"                    
            return before_version,after_version,update_status

    def system_fw_update(self, attr):
        ini_path = os.path.join(os.getcwd(),'config.ini')
        config = configparser.ConfigParser()
        config.read(ini_path)
        try:
            target = config.get('Target','update_target')
            image_path_inputs = {
                "XD220V": config.get('Image', 'update_image_path_xd220V'),
                "XD225V": config.get('Image', 'update_image_path_xd225V'),
                "XD295V": config.get('Image', 'update_image_path_xd295V'),
                }
        except:
            pass
        
        if target=="BMC" or target=="PDBPIC":
            return {'ret': False, 'changed': True, 'msg': 'Must update BMC and PDB together using pdb_bmc_update.yml'}
        ## have a check that atleast one image path set based out of the above new logic
        if not any(image_path_inputs.values()):
            return {'ret': False, 'changed': True, 'msg': 'Must specify atleast one update_image_path'}
        
        IP = attr.get('baseuri')
        username = attr.get('username')
        password = attr.get('password')
        update_status = "success"
        is_target_supported=False
        image_path="NA"
        csv_file_name = attr.get('output_file_name')
        model = self.get_model()
        image_type = None
        if image_type is None:
            image_type = attr.get('update_image_type')

        if not os.path.exists(csv_file_name):
            f = open(csv_file_name, "w")
            if target == "PDBPIC_BMC":
                to_write="IP_Address,Model,BMC,BIOS,MainCPLD,PDBPIC,HDDBPPIC\n"
            else:
                to_write="IP_Address,Model,"+target+'_Pre_Ver,'+target+'_Post_Ver,'+"Update_Status\n"
            f.write(to_write)
            f.close() 

        if model=="NA":
            update_status="unreachable/unsupported_system" 
            lis=[IP,model,"NA","NA",update_status]
            new_data=",".join(lis)
            return {'ret': True,'changed': True, 'msg': str(new_data)}
        elif partial_models[model.upper()] not in supported_models:
            update_status="unsupported_model" 
            lis=[IP,model,"NA","NA",update_status]
            new_data=",".join(lis)
            return {'ret': True,'changed': True, 'msg': str(new_data)}
        else:
            image_path = image_path_inputs[partial_models[model.upper()]]

            if target!="PDBPIC_BMC" and not os.path.isfile(image_path):
                update_status = "NA_fw_file_absent"
                lis=[IP,model,"NA","NA",update_status]
                new_data=",".join(lis)
                return {'ret': True,'changed': True, 'msg': str(new_data)}
            else:
                is_target_supported = self.target_supported(model,target)

                if target == "PDBPIC_BMC":
                    target = attr.get('target')
                if not is_target_supported:
                    update_status="target_not_supported"
                    lis=[IP,model,"NA","NA",update_status]    
                    new_data=",".join(lis)
                    return {'ret': True,'changed': True, 'msg': str(new_data)}
                elif target == "PDBPIC":
                    split_image_path = image_path.split()
                    result = self.check_master_ipmi(IP,username,password)
                    if not result:
                        update_status="Please update PDBPIC from the master node"
                        lis=[IP,model,"NA","NA",update_status]    
                        new_data=",".join(lis)
                        return {'ret': True,'changed': True, 'msg': str(new_data)}
                    bef_ver,aft_ver,update_status=self.helper_update(update_status,"PDBPIC",split_image_path[0],image_type,IP,username,password,model)
                    if update_status.lower()!="success":
                        return {'ret': False, 'changed': True, 'msg': f'Failed post for the server: {IP}'}
                    lis=[IP,model,bef_ver,aft_ver,update_status]
                elif target == "BMC":
                    split_image_path = image_path.split()
                    result = self.check_non_master_ipmi(IP,username,password)
                    if not result:
                        update_status="Please update BMC using the BMC_Master target from the master node"
                        lis=[IP,model,"NA","NA",update_status]    
                        new_data=",".join(lis)
                        return {'ret': True,'changed': True, 'msg': str(new_data)}
                    bef_ver,aft_ver,update_status=self.helper_update(update_status,"BMC",split_image_path[1],image_type,IP,username,password,model)
                    if update_status.lower()!="success":
                        return {'ret': False, 'changed': True, 'msg': f'Failed post for the server: {IP}'}
                    lis=[IP,model,bef_ver,aft_ver,update_status]
                elif target == "BMC_Master":
                    split_image_path = image_path.split()
                    result = self.check_master_ipmi(IP,username,password)
                    if not result:
                        update_status="Please update BMC using the BMC target from the Non-Master node"
                        lis=[IP,model,"NA","NA",update_status]    
                        new_data=",".join(lis)
                        return {'ret': True,'changed': True, 'msg': str(new_data)}
                    bef_ver,aft_ver,update_status=self.helper_update(update_status,"BMC",split_image_path[1],image_type,IP,username,password,model)
                    if update_status.lower()!="success":
                        return {'ret': False, 'changed': True, 'msg': f'Failed post for the server: {IP}'}
                    lis=[IP,model,bef_ver,aft_ver,update_status]
                else:
                    bef_ver,aft_ver,update_status=self.helper_update(update_status,target,image_path,image_type,IP,username,password,model)
                    lis=[IP,model,bef_ver,aft_ver,update_status]
                new_data=",".join(lis)
                return {'ret': True,'changed': True, 'msg': str(new_data)}
