# Details on Ansible

inventory : Create an Ansible inventory file that lists the target systems you want to update. This file should contain the necessary details to connect to the systems, such as IP addresses.

<br />

system_credentials.yml : This file contains the credentials of the target systems.

<br />

Playbooks : Ansible playbooks are defined with the tasks required to update the different components of system firmware, fetch system firmware inventory for the supported Cray XD servers and a playbook to view power states or to power on or to power off Cray XD670 nodes.

<br />

Run the Playbooks : Execute the playbook using the ansible-playbook command, providing the inventory file and the playbook file as arguments. Ansible will connect to the target systems specified in the inventory and execute the tasks defined in the playbook.



# Ansible Firmware Update Tool

This repository contains ansible modules, playbooks to perform firmware upgrade HPE Cray XD225v, HPE Cray XD295v, HPE Cray XD220v, HPE Cray XD670 and HPE Cray XD665



# Pre-requisites

1. Ansible should be installed

2. Ansible collection module community.general >= 6.4.0



To install Community general package use:



```

ansible-galaxy collection install community.general

```

3. Run setup.yml to install ipmitool required for Power cycle

```

ansible-playbook -i inventory setup.yml

```



# Update inventory and system_credentials.yml

Update the IP address under [xds] variable like the below:

```

[xds]

ip1

ip2

```

Update the IP address its corresponding username and password in system_credentials.yml as follows:

```

---

inputs:

   ip1:

      user: "<ip1 user name>"

      password: "<ip1 password"

   ip2:

      user: "<ip2 user name>"

      password: "<ip2 password>"



```



# Scripts

1. system_firmware_update.yml : Playbook to perform firmware upgrade which requires target and the respective firmware files(hpm file) to be mentioned in the configuration file config.ini

2. get_system_firmware_inventory.yml : Playbook to fetch the system firmware inventory information

3. power_state_XD670.yml: Playbook to fetch the power state information, to power on, to power off the Cray XD670 nodes.


# Targets supported for Updates:

For HPE Cray XD220v, HPE Cray XD225V and HPE Cray XD295 supported targets are:

- BMC

- BIOS

- MainCPLD

- HDDBPPIC

- PDBPIC 



For HPE Cray XD XD665 supported targets are:

- BMC

- BIOS

- RT_NVME

- RT_OTHER

- RT_SA

- PDB

- MainCPLD

- HDDCtrlr

- UBM6


For HPE Cray XD670 supported targets are:

- BMC 

- BMC Image2
	
- BIOS

- BIOS2

- MB_CPLD1

- SCM_CPLD1

- BPB_CPLD1
	
- BPB_CPLD2


# Firmware Upgrade


The playbook `system_firmware_update.yml` is used to perform the firmware upgrade and the detailed procedure is listed below:

1. Update system_credentials.yml and cray servers details in the inventory file under [xds] Specifically the remotely accessible cray ip addresses

2. Update the config.ini

   - update_target = Name of the target component to be upgraded, these are case sensitive refer to `Targets supported for Updates` [Required]

   - update_image_path_xd220v : Path to local hpm file for HPE Cray XD220v

   - update_image_path_xd225v :  Path to local hpm file for HPE Cray XD225v
   
   - update_image_path_xd295v : Path to local hpm file for HPE Cray XD295v

   - update_image_path_xd665 : Path to local hpm file for HPE Cray XD665

   - update_image_path_xd670 : Path to local hpm file for HPE Cray XD670


3. Run the ansible playbook:

   ```ansible-playbook -i inventory system_firmware_update.yml -e @system_credentials.yml -e @cray-vault --ask-vault-pass```

   After the firmware target is upgraded, the server reboots for all required components.



# Firmware Inventory

The playbook `get_system_firmware_inventory.yml` is used to fetch the firmware inventory information of the cray servers

1. Update the following details in inputs.yml and inventory file accordingly

2. Run the ansible playbook:

   `ansible-playbook -i inventory get_system_firmware_inventory.yml  -e @system_credentials..yml`



# Get Power State of the Cray XD670 nodes

The playbook `power_state_XD670.yml` is used to fetch the power state, power on, power off the Cray XD670 nodes.

1. Update the following details in inputs.yml and inventory file, config file for required power_state accordingly

2. Run the ansible playbook:

   `ansible-playbook -i inventory  power_state_XD670.yml -e @system_credentials..yml`


# Ansible-vault

This ansible-vault encrypts the file containing sensitive data. And can be used during execution by providing the key.



To encrypt the file

```

ansible-vault encrypt file_name

```



To decypt the file 

```

ansible-vault decrypt file_name

```



To edit the file

```

ansible-vault edit file_name

```