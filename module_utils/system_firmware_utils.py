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
    "XD220V": ["BMC", "BIOS", "MainCPLD", "HDDBPPIC", "PDBPIC", "GPU"],
    "XD225V": ["BMC", "BIOS", "MainCPLD", "HDDBPPIC", "PDBPIC", "GPU"],
    "XD295V": ["BMC", "BIOS", "MainCPLD", "HDDBPPIC", "PDBPIC", "GPU"],
}
# supported_targets = {
#     "HPE CRAY XD220V": ["BMC", "BIOS", "MainCPLD", "HDDBPPIC", "PDBPIC"],
#     "HPE CRAY SC XD220V": ["BMC", "BIOS", "MainCPLD", "HDDBPPIC", "PDBPIC"],
#     "HPE CRAY XD225V": ["BMC", "BIOS", "MainCPLD", "HDDBPPIC", "PDBPIC"],
#     "HPE CRAY SC XD225V": ["BMC", "BIOS", "MainCPLD", "HDDBPPIC", "PDBPIC"],
#     "HPE CRAY XD295V": ["BMC", "BIOS", "MainCPLD", "HDDBPPIC", "PDBPIC"],
#     "HPE CRAY SC XD295V": ["BMC", "BIOS", "MainCPLD", "HDDBPPIC", "PDBPIC"],
# }


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
#config = configparser.ConfigParser()

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
        #print("****", model,partial_models)
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
                return "failed_FI_GET_call/no_version_field"
            try:
                version = response['data']['Version']
                return version
            except:
                version = response['Version']
                return version
        except:
            return "failed_FI_GET_call/no_version_field"
    
 
    def AC_PC_redfish(self):
        payload = {"ResetType": "ForceRestart"}
        target_uri = "/redfish/v1/Systems/Self/Actions/ComputerSystem.Reset"
        response1 = self.post_request(self.root_uri + target_uri, payload)
        time.sleep(180)
        target_uri = "/redfish/v1/Chassis/Self/Actions/Chassis.Reset"
        response2 = self.post_request(self.root_uri + target_uri, payload)
        time.sleep(180)
        return response1 or response2

    def AC_PC_ipmi(self, IP, username, password, routing_value): 
        try:
            command='ipmitool -I lanplus -H '+IP+' -U '+username+' -P '+password+' raw '+ routing_value
            subprocess.run(command, shell=True, check=True, timeout=15)
            time.sleep(300)
            self.power_on()
            return True
        except:
            return False

    def get_sys_fw_inventory(self,attr):
        IP = attr.get('baseuri')
        # username = attr.get('username')
        # password = attr.get('password')
        csv_file_name = attr.get('output_file_name')
        model = self.get_model()
        if not os.path.exists(csv_file_name):      
            f = open(csv_file_name, "w")
            to_write="IP_Address,Model,BMC,BIOS,MainCPLD,PDBPIC,HDDBPPIC\n"
            f.write(to_write)
            f.close()                                                               
        #print("******model of is", IP, model)
        entry=[]
        entry.append(IP)
        if model=="NA":
            #print("***", model.upper(), partial_models[model.upper()],supported_models)
            # if model=="NA":
            entry.append("unreachable/unsupported_system") #unreachable or not having model field correctly, i.e not even a XD system
            for target in all_targets:
                entry.append("NA")
        elif partial_models[model.upper()] not in supported_models: #might be a Cray XD like XD685 which is not yet supported
            entry.append("unsupported_model, ",partial_models)
            for target in all_targets:
                entry.append("NA")
            #return {'ret': True, 'changed': True, 'msg': 'Must specify systems of only the supported models. Please check the model of %s'%(IP)}
        else:
            entry.append(model)
            for target in all_targets:
                if target in supported_targets[partial_models[model.upper()]]:
                    version=self.get_fw_version(target)
                    # if version.startswith("failed"):
                    #     version="NA" #"no_comp/no_version"
                else:
                    version = "NA"
                entry.append(version)
        new_data=",".join(entry)
        return {'ret': True,'changed': True, 'msg': str(new_data)}

    def helper_update(self,update_status,target,image_path,image_type,IP,username,password,model):
        before_version=None
        after_version=None
        update_status=None
        if target!="BPB_CPLD" and target!="SCM_CPLD1" and target!="MB_CPLD1" and target!="GPU":
            before_version = self.get_fw_version(target)
            if target=="BMC" and "XD670" in model.upper() and "failed" in before_version:
                target="BMCImage1"
                before_version = self.get_fw_version(target)
            #after_version=None
        else:
            before_version = "NA"
            after_version="NA"
        if not before_version.startswith("failed"):
            #proceed for update
            response = self.get_request(self.root_uri + "/redfish/v1/UpdateService")
            if response['ret'] is False:
                update_status="UpdateService api not found"
            else:
                data = response['data']
                if 'MultipartHttpPushUri' in data:
                    headers = {'Expect': 'Continue','Content-Type': 'multipart/form-data'}
                    body = {}
                    if target!="BPB_CPLD":
                        if image_type=="PLDM":
                            targets_uri='/redfish/v1/UpdateService/upload/'
                            body['UpdateParameters'] = (None, json.dumps({"Targets": []}), 'application/json')
                        else:
                            targets_uri='/redfish/v1/UpdateService/FirmwareInventory/'+target+'/'
                            body['UpdateParameters'] = (None, json.dumps({"Targets": [targets_uri]}), 'application/json')
                    else:
                        body['UpdateParameters'] = (None, json.dumps({"Targets": ['/redfish/v1/UpdateService/FirmwareInventory/BPB_CPLD1/', '/redfish/v1/UpdateService/FirmwareInventory/BPB_CPLD2/']}), 'application/json')
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
                            time.sleep(500)
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
                                        time.sleep(300)
                                    elif reb=="AC_PC_ipmi":
                                        result = self.AC_PC_ipmi(IP, username, password, routing[partial_models[model.upper()]]) #based on the model end routing code changes 
                                        if not result:
                                            update_status="reboot_failed"
                                            break 
            
                            ## if target=="MB_CPLD1" or "BPB" in target:
                            ##    ##turn node back to on -- call power_on_node function
                            ##    self.power_on()
        
                            if update_status.lower()=="success":
                                #call version of respective target and store versions after update    
                                time.sleep(180) #extra time requiring as of now for systems under test
                                if target!="BPB_CPLD" and target!="SCM_CPLD1" and target!="MB_CPLD1" and target!="GPU":
                                    after_version=self.get_fw_version(target)
                            else:
                                if target!="BPB_CPLD" and target!="SCM_CPLD1" and target!="MB_CPLD1" and target!="GPU":
                                    after_version="NA"
                                #update_status="failed"

            if target!="BPB_CPLD" and target!="SCM_CPLD1" and target!="MB_CPLD1" and target!="GPU":                     
                return before_version,after_version,update_status
            else:
                return update_status
        else:
            #print("in line 341:", before_version,after_version,update_status)
            update_status="NA"
            if target!="BPB_CPLD" and target!="SCM_CPLD1" and target!="MB_CPLD1" and target!="GPU": 
                after_version="NA"                    
                return before_version,after_version,update_status
            else:
                return update_status
        
    def system_fw_update(self, attr):
        ini_path = os.path.join(os.getcwd(),'config.ini')
        config = configparser.ConfigParser()
        config.read(ini_path)
        key = ""
        try:
            target = config.get('Target','update_target')
            image_path_inputs = {
                "XD220V": config.get('Image', 'update_image_path_xd220V'),
                "XD225V": config.get('Image', 'update_image_path_xd225V'),
                "XD295V": config.get('Image', 'update_image_path_xd295V'),
                "XD665": config.get('Image', 'update_image_path_xd665'),
                "XD670": config.get('Image', 'update_image_path_xd670'),
                }
        except:
            pass

        ## have a check that atleast one image path set based out of the above new logic
        if not any(image_path_inputs.values()):
            return {'ret': False, 'changed': True, 'msg': 'Must specify atleast one update_image_path'}
        
        IP = attr.get('baseuri')
        username = attr.get('username')
        password = attr.get('password')
        update_status = "success"
        before_version=None
        after_version=None
        is_target_supported=False
        # before_version="NA"
        # after_version="NA"
        image_path="NA"
        csv_file_name = attr.get('output_file_name')
        image_type = config.get('Firmware_type','update_image_type')
        if image_type is None:
            image_type = attr.get('update_image_type')

        if target=="" or target.upper() in XD670_unsupported_targets:
            return {'ret': False, 'changed': True, 'msg': 'Must specify the correct target for firmware update'}   
       
        model = self.get_model()

        if not os.path.exists(csv_file_name):
            f = open(csv_file_name, "w")
            if target=="BPB_CPLD" or target=="SCM_CPLD1_MB_CPLD1":
                to_write="IP_Address,Model,Update_Status,Remarks\n"                 
            else:
                to_write="IP_Address,Model,"+target+'_Pre_Ver,'+target+'_Post_Ver,'+"Update_Status\n"
            f.write(to_write)
            f.close() 

        ## not needed as a check is made in get model for BMC target of XD670
        # #check if model is Cray XD670 and target is BMC assign default value of BMC as BMCImage1
        # if (model.upper() == "HPE CRAY XD670" or model.upper()=="HPE CRAY SC XD670 DLC" or model.upper()=="HPE CRAY SC XD670") and target == "BMC":
        #     target = "BMCImage1"  
        if model=="NA":
            update_status="unreachable/unsupported_system" 
            if target=="SCM_CPLD1_MB_CPLD1" or target=="BPB_CPLD":
                lis=[IP,model,update_status,"NA"]
            else:
                lis=[IP,model,"NA","NA",update_status]
            new_data=",".join(lis)
            return {'ret': True,'changed': True, 'msg': str(new_data)}
        elif partial_models[model.upper()] not in supported_models:
            update_status="unsupported_model" 
            if target=="SCM_CPLD1_MB_CPLD1" or target=="BPB_CPLD":
                lis=[IP,model,update_status,"NA"]
            else:
                lis=[IP,model,"NA","NA",update_status]
            new_data=",".join(lis)
            return {'ret': True,'changed': True, 'msg': str(new_data)}
        else:
            image_path = image_path_inputs[partial_models[model.upper()]]
            if "XD670" in model and "CPLD" in target.upper():
                if target.upper()=="BPB_CPLD":
                    is_target_supported=True
                power_state = self.power_state()
                if power_state.lower() != "on":
                    update_status="NA"
                    lis=[IP,model,update_status,"node is not ON, please power on the node using the playbook power_state_XD670.yml"]
                    new_data=",".join(lis)
                    return {'ret': True,'changed': True, 'msg': str(new_data)}
                    #return {'ret': False, 'changed': True,'msg': 'System Firmware Update skipped due to powered off state of the node for Cray XD 670, Node needs to be powered on for CPLD firmware updates'}
                elif target=='SCM_CPLD1_MB_CPLD1':
                    is_target_supported=True
                    image_paths=image_path_inputs["XD670"].split()
                    if len(image_paths)!=2: 
                        return {'ret': False, 'changed': True,'msg': 'Must specify exactly 2 image_paths, first for SCM_CPLD1 of Cray XD670 and second for MB_CPLD1 of Cray XD670'}
                    for img_path in image_paths:
                        if not os.path.isfile(img_path):
                            #update_status = "fw_file_absent"
                            return {'ret': False, 'changed': True,'msg': 'Must specify correct image_paths for SCM_CPLD1_MB_CPLD1, first for SCM_CPLD1 of Cray XD670 and second for MB_CPLD1 of Cray XD670'}
            
            if target!="SCM_CPLD1_MB_CPLD1" and not os.path.isfile(image_path):
                update_status = "NA_fw_file_absent"
                if target=="BPB_CPLD":
                    lis=[IP,model,update_status,"NA"]
                else:
                    lis=[IP,model,"NA","NA",update_status]
                new_data=",".join(lis)
                return {'ret': True,'changed': True, 'msg': str(new_data)}
            else:

                if target!="SCM_CPLD1_MB_CPLD1" and target!="BPB_CPLD":
                    is_target_supported = self.target_supported(model,target)
                
                # if "XD670" in model.upper() and (target=="BMC" or target=="BPB_CPLD"):
                #     is_target_supported=True
                
                if not is_target_supported:
                    update_status="target_not_supported"
                    if target=="SCM_CPLD1_MB_CPLD1" or target=="BPB_CPLD":
                        lis=[IP,model,update_status,"NA"]
                    else:
                        lis=[IP,model,"NA","NA",update_status]    
                    new_data=",".join(lis)
                    return {'ret': True,'changed': True, 'msg': str(new_data)}
                    #return {'ret': False, 'changed': True,'msg': "Target '%s' not supported for the model '%s'. Please change the target or remove this specific model server entries from inventory and try again" %(target,model)}
                else:
                    # #check if model is Cray XD670 and target is BMC assign default value of BMC as BMCImage1
                    # if (model.upper() == "HPE CRAY XD670" or model.upper()=="HPE CRAY SC XD670 DLC" or model.upper()=="HPE CRAY SC XD670") and target == "BMC":
                    #     target = "BMCImage1"

                    #call version of respective target and store versions before update
                    if target=="SCM_CPLD1_MB_CPLD1":
                        update_status=self.helper_update(update_status,"SCM_CPLD1",image_paths[0],image_type,IP,username,password,model)
                        if update_status.lower()=="success": #SCM has updates successfully, proceed for MB_CPLD1 update
                            #check node to be off -- call power_off_node funcn
                            power_state = self.power_state()
                            if power_state.lower() == "on":
                                self.power_off()
                                power_state = self.power_state()
                                if power_state.lower() == "on":
                                    lis=[IP,model,"NA","MB_CPLD1 requires node off, tried powering off the node, but failed to power off"] #unable to power off node for MB_CPLD1
                                    #'msg': 'System Firmware Update skipped due to powered ON state of the node for Cray XD 670, Node needs to be powered OFF for MB_CPLD1 firmware updates, tried powering off, but unable to power off'
                                else:
                                    update_status=self.helper_update(update_status,"MB_CPLD1",image_paths[1],image_type,IP,username,password,model)  
                                    if update_status.lower() == "success":
                                        remarks="Please plug out and plug in power cables physically"
                                    else:
                                        remarks="Please reflash the firmware and DO NOT DO physical power cycle"
                                    lis=[IP,model,update_status,remarks]
                    elif target=="BPB_CPLD":
                        update_status=self.helper_update(update_status,target,image_path,image_type,IP,username,password,model)
                        if update_status.lower() == "success":
                            remarks="Please plug out and plug in power cables physically"
                        else:
                            remarks="Please reflash the firmware and DO NOT DO physical power cycle"
                        lis=[IP,model,update_status,remarks]
                    else:
                        bef_ver,aft_ver,update_status=self.helper_update(update_status,target,image_path,image_type,IP,username,password,model)
                        lis=[IP,model,bef_ver,aft_ver,update_status]
                    new_data=",".join(lis)
                    return {'ret': True,'changed': True, 'msg': str(new_data)}

                    
