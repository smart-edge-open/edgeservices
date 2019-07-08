```text
SPDX-License-Identifier: Apache-2.0
Copyright © 2019 Intel Corporation and Smart-Edge.com, Inc.
```

# 1. Introduction
## Purpose
This document is intended for OpenNESS Edge Node setup and serves as a guide on setting up OpenNESS Edge Node product on required hardware test platform using delivered automation scripts. 

## 1.1. Scope
Section 2 – Describes software components being used by OpenNESS Edge Node

Section 3 – Shows available environment setup variants

Section 4 – Details on hardware requirements

Section 5 – Hardware setup instructions

Section 6 – Operating system set up

Section 7 – Running automation scripts

Section 8 – Troubleshooting

Section 9 - Change Log

## 1.2. Terminology
|                    |                                                                                   |
|--------------------|-----------------------------------------------------------------------------------|
| Ansible            | Open source automation platform                                                   |
| Container          | Executable package containing application code, runtime, libraries and settings.  |
| Docker             | Platform for creating and running applications inside containers                  |
| DPDK               | Data Plane Development Kit                                                        |
| OpenNESS           | Controller Community edition                                                      |
| OpenNESS Edge Node | This product name                                                                 |
| OS                 | Operating System                                                                  |
| QEMU               |Quick Emulator; open source emulator for hardware virtualization                   |
| RPM                | RPM Package Manager                                                               |
| VM                 | Virtual Machine                                                                   |
# 2. Software overview

OpenNESS Edge Node uses a set of open source applications and framework, both inside the product and during installation/deployment process.

OpenNESS User and developer Prerequisites: 
- Understanding and usage of virtualization environment based on Libvirt 
- Understanding and usage of Container environment based on Dockers 
- Understanding and usage of Cloud Native environment based on Kubernetes
- Basic understanding of Networking 
- Go lang for OpenNESS microservices 
- C lang and DPDK for dataplane 
- HTTP REST, json, gRPC, Protobuf for API 
- Amazon AWS IoT Greengrass Core for Cloud adapters 
- Baidu Cloud for Cloud adapters 
- TLS for authentication  

> NOTE: In some cases the OpenNESS package might be provided to you which contains all the required OpenNESS packaged. Cloning of repository is not required in that case.

## 2.1. CentOS Linux 
OpenNESS Edge Node runs on the CentOS 7.6 x86_64 operating system. The same operating system is used for building product components and deploying/running them on a dedicated hardware platform.
Intel suggests installing a minimal amount of RPM Package Manager packages inside operating system, so the "Minimal" ISO of CentOS is recommended for use when preparing any of the test machine.

## 2.2. Additional software
OpenNESS Edge Node uses open source software for building, deployment and running applications, most importantly Quick Emulator (QEMU), Docker, Data Plane Development Kit (DPDK), and Ansible.
There is no need to install these software packages manually. All dependencies, including downloading them from the internet will be handled by automation scripts.

### 2.2.1. QEMU
On CentOS Linux the latest tested version of Quick Emulator (QEMU) is v3.0.1. It will be installed automatically by automation scripts.

### 2.2.2. Docker
Community Edition of Docker software is used. The latest tested versions is v18.09.6. It will be installed automatically.

### 2.2.3. DPDK
DPDK v18.08 is required and is installed automatically to compile and run all applications. 

### 2.2.4. GO language
The latest version checked and used is 1.12.4 (installed automatically).

### 2.2.5. Ansible
Ansible is an automation platform used for configuring the operating system, installing packages and additional software, and resolving all package/software dependencies automatically, without user interaction.

It will be installed automatically by the first automation script being ran on hardware with newly installed CentOS operating system.

# 3. Environment Setup variants
OpenNESS Edge Node requires CentOS 7.6 x64 operating system to be installed on the hardware. 
For building product binaries, images and containers only one server is required. 

![OpenNESS Build and Execution setup](ug-images/openness_setup.png)

In this scenario, all actions will take place on the same machine.
> NOTE: For a dual server setup, where one server is being used for building binaries, product images, and a second server for deploying them in a production server, refer to the README.md documents under the following repository subfolders: `./scripts/ansible/build_server` and `./scripts/ansible/deploy_server` that will guide you through a different setup on two machines.

OpenNESS supports Network Edge and On-Premise edge deployment. For details of these two deployment model please refer to the OpenNESS architecture specification. 
- Network Edge deployment is based on Kubernetes 
- On-Premise Edge deployment is based on Docker Containers and VMs based on libvirt. 

The OpenNESS Edge Node and OpenNESS controller components build would remain unchanged for both the deployments. For the Network Edge deployment this document assumes that a Kubernetes cluster is setup with Kubernetes master and Node is added to the cluster. The document does not provide the steps for setting up Kubernetes cluster. 

Reference for setting up Kubernetes cluster on CentOS: https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/

OpenNESS supports Network Edge and On-Premise edge deployment. For details of these two deployment model please refer to the OpenNESS architecture specification. 
- Network Edge deployment is based on Kubernetes 
- On-Premise Edge deployment is based on Docker Containers and VMs based on libvirt. 

The OpenNESS Edge Node and OpenNESS controller components build would remain unchanged for both the deployments. For the Network Edge deployment this document assumes that a Kubernetes cluster is setup with Kubernetes master and Node is added to the cluster. The document does not provide the steps for setting up Kubernetes cluster. 

Reference for setting up Kubernetes cluster on CentOS: https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/

# 4. Hardware requirements

This chapter describes the hardware required to run OpenNESS Edge Node.

## 4.1. Supported platform
The OpenNESS Edge Node product has been tested using the following hardware specification:

- Super Micro 3U form factor chassis server, product SKU code: 835TQ-R920B
- Motherboard type: X11SDV-16C-TP8F
  https://www.supermicro.com/products/motherboard/Xeon/D/X11SDV-16C-TP8F.cfm
- Intel® Xeon® Processor D-2183IT

|                  |                                                                                            |
|------------------|--------------------------------------------------------------------------------------------|
| SKX-SP           | Compute Node based on SKX-SP                                                               |
| Board            | WolfPass S2600WFQ server board(symmetrical (symmetrical Intel® QuickAccess Technology) CPU |
|                  | 2 x Intel® Xeon® Gold 6148 CPU @ 2.40GHz                                                   |
|                  | 2 x associated Heatsink                                                                    |
| Memory           | 12x Micron* 16GB DDR4 2400MHz DIMMS* [2666 for PnP]                                        |
| Chassis          | 2U Rackmount Server Enclosure                                                              |
| Storage          | Intel® M.2 SSDSCKJW360H6 360G                                                              |
| NIC              | 1x Intel® Fortville NIC  X710DA4  SFP+ ( PCIe card to CPU-0)                               |
| QAT              | Intel® Quick Assist Adapter Device 37c8                                                    |
|                  | (Symmetrical design) LBG integrated                                                        |
| NIC on board     | Intel® Ethernet Controller I210 (for management)                                           |
| Other card       | 2x PCIe* Riser cards                                                                       |

# 5. Hardware setup
There are no special requirements for setting up hardware compared to a typical network server setup, except modifying BIOS settings and making sure the server is able to reach the internet (required to download other packages during server software setup).

## 5.1. BIOS revision upgrade
Before proceeding, make sure the BIOS is updated to the latest available stable release.
Please refer to the manufacturer user guide on upgrading BIOS firmware.

## 5.2. BIOS setting
There are few required BIOS settings for OpenNESS Edge Node server that operator needs to set. They are CPU and power management related.
It's recommended to first reset BIOS to factory defaults, and then set the following options as shown below:
- BIOS - Advanced - Processor Configuration:
  - Intel(R) Hyper-Threading = DISABLED
  - Intel(R) Virtualization Technology = ENABLED
- BIOS - Advanced - Power & Performance:
  - Workload Configuration = BALANCED
- BIOS - Advanced - Power & Performance - CPU C State Control:
  - Package C-State = C0C1 state
  - C1E = DISABLED
  - PRocessor C6 = DISABLED
- BIOS - Advanced - Power & Performance - Hardware P States:
  - Hardware P-States = DISABLED
- BIOS - Advanced - Power & Performance - CPU P State Control:
  - Enchanced Intel SpeedStep(R) Tech = DISABLED
  - Intel(R) Turbo Boost Technology = DISABLED
  - Energy Efficient Turbo = DISABLED

# 6. CentOS operating system set up
The evaluated version of CentOS Linux is v7.6.1810 (Minimal). The ISO file is available from mirror sites listed at the link:
https://wiki.centos.org/Download

> NOTE: It is recommended to use a Minimal CentOS Linux installation media, as only a minimal set of packages will be installed on disk. This brings the benefits of faster installation time, reduced OS complexity and overload (GUI, needless services running in background).

> NOTE: Running CentOS operating system for OpenNESS Edge Node Build/Deploy server as a virtual machine is not supported. Install operating system directly on physical server.

## 6.1. Base OS installation options
Since the minimal installation image does not contain any options for packages to be installed, the only options the operator has to set are:
- Correct time and timezone
- The root user password
- The destination media location (disk/partitions)
- Network settings (IP addresses on chosen NIC) for accessing the internet

## 6.2. Proxy setup
If the server is not using a proxy to access the internet, skip this subsection.
If a proxy is used, the following steps configure the operating system and services that will be run later by automation scripts.
Example configurations of the proxy for each service or operating system component are available for preview in subfolder ``` ./scripts/ansible/examples/proxy```.
Their structures reflect the structure in your operating system. 
It is advised to not copy them directly to your operating system but instead, modify your own proxy configurations to contain items available in those example files.

#### OS setup files:
* `/etc/environment`

   Make sure that your current environment file contains variables for `http_proxy` and `HTTP_PROXY`, and, if `https proxy` is 
   also used, then also include `https_proxy` and `HTTPS_PROXY` in your config file. Additionally, include `ftp_proxy` and `FTP_PROXY` variables with correct IP and port addresses.

   See example in provided file in folder: `./scripts/ansible/examples/proxy/etc/environment`
* `/etc/yum.conf`

   Add one line for http proxy to your `yum.conf` file as shown in `./scripts/ansible/examples/proxy/etc/yum.conf`
   > Tip: Make sure the port is correct and slash character (/) is present at the end of the line.

#### Docker service
* `/etc/systemd/system/docker.service.d/http-proxy.conf`

   A sample configuration for docker service is inside file `./scripts/ansible/examples/proxy/etc/systemd/system/docker.service.d/http-proxy.conf`

   If you do not have Docker configured and this file is missing in the `/etc` folder, you may copy this example file to the given path in the 
   `/etc` folder and modify it according to your needs.

* `/root/.docker/config.json`

   A sample configuration is inside the file `./scripts/ansible/examples/proxy/root/.docker/config.json`
   
> NOTE: Once proxy setup is complete, it is advised to reboot the server or at least log out and log in again, so that `/etc/environment` will be read by the login service and shell startup scripts.

> NOTE: If you are not sure whether your proxy settings work, run a simple `yum update` command to check whether the internet is reachable with the given proxy settings. 

## 6.3. Packages and OS upgrade
After the CentOS* Linux* installation and proxy setup are complete and the server reboots from the local disk, it is time to upgrade all software packages to the newest version.

Login as root user, and run the following command to upgrade the installed packages:
```
# yum upgrade
```
> NOTE: If you are using a network proxy, make sure it is set up correctly before running any Ansible script.

# 7. Automation scripts
OpenNESS Edge Node provides automation scripts to minimize required user interaction and speed up the process of software set up.
Scripts provided require only access to the internet network and, when run, install required packages, build software components, and import freshly compiled and built product packages (images). The last action ran in the last script is to bring up all required components to have a fully functional product running.

Automation scripts are located inside the repository/subfolder `edgenode`  in the  ```./scripts/ansible/single_server```  folder. Their names represent the order in which they shall be run, for example:
- 01_setup_server.sh
- 02_install_tools.sh
- 03_build_and_deploy.sh

> NOTE: For dual server setup, refer to the README.md files in the `./scripts/ansible/build_server` and `./scripts/ansible/deploy_server` subfolders. They contain detailed instructions on how to run all scripts and describe an expected outcome.

> NOTE: It is advised to set up and configure OpenNESS Edge Controller before setting up Edge Node, as operator is required to enter Controller IP address and Controller Root CA certificate before Edge Node is set up. Guide for setting up Controller can be found in the main folder of OpenNESS Edge Controller repository.

## 7.1. Preconditions
The following actions must be complete prior to running OpenNESS Edge Node automation setup scripts on the server:
- CentOS 7.6 x64 Linux must be running (Minimal image)
- Time and timezone are set correctly
- Access to the internet is possible 
- Network access proxy, if used, has been set up correctly and proxy config files from `./scripts/ansible/examples/proxy` subfolder were copied to the correct locations on the local disk
- Firewall allows outgoing TCP ports `21,80,443` (or proxy ports if proxy is used) and UDP `53`
- Operating system software is up to date (run `yum update` before running any scripts listed below)
- Root account is required (each script requires root permissions)
- Server terminal console access or remote ssh access is needed (only on of them)
- Controller IP address is known to operator
- Controller ROOT CA certificate is available to operator

>  NOTE: If SELinux is enabled, it will be disabled temporarily as the scripts are run, but also permanently set to disabled (permissive mode) after the first server reboot.

## 7.2. Configure Controller connectivity
Before configuring Edge Node server from automation scripts below (see chapter 7.3), modify its configuration files, so that automation scripts will be ready to accept incoming connections from Controller:
1. Open file: <br>
   `./scripts/ansible/deploy_server/vars/defaults.yml` <br> and  modify Controller IP address and port, like: <br> `enrollment_endpoint: "1.2.3.4:8081"`.
2. Copy Controller ROOT CA certificate from Controller using `docker cp edgecontroller_cce_1:/artifacts/certificates/ca/cert.pem` to local controller folder first and then copy it to the following folder: <br>`/etc/pki/tls/certs/controller-root-ca.pem` on the Edge node. 
3. Now you are ready to to run automation scripts.


## 7.3. Run automation scripts
Automation scripts are located in the repository subfolder `./scripts/ansible/single_server`:
- 01_setup_server.sh
- 02_install_tools.sh
- 03_build_and_deploy.sh

Scripts shall be run in the order listed above.
> NOTE: They can be run locally from the server console or through an SSH session.

> NOTE: Each scripts shall be run as root user directly, not via `sudo`.

### Steps to follow:
1. Enter the folder with scripts for single server:
```
  # cd <edgenode_folder_or_repository>/scripts/ansible/single_server/
```
2. Run script `01_setup_server.sh`.
3. Reboot server if requested/informed by the script.
4. Run script `02_install_tools.sh`.
5. Once previous script completes, run the last script: `03_build_and_deploy.sh`.

    At some point, the script will print a key on the console.
    
    This key will be needed on the controller.

    >NOTE: If the script terminates at "Building images" step and says about failing docker-compose command, run the following script to resolve issue automatically: `./scripts/ansible/common/scripts/reinstall-urllib3-module.sh`. After that, run script `03_build_and_deploy.sh` again. 
6. Wait for communication from controller side and wait for certificates exchange.
7. After communication is established and certificates are uploaded automatically to this server, the script will bring up all product components and finish.

### Expected result:
If automation scripts are run correctly, the expected result is all Docker containers are running or created. 

To check whether all components are running, run the ` # docker ps -a` command 
and inspect each component status in the `STATUS` column. Each component shall have `CREATED` or `UP` status.

### Unexpected results:
- Script fails – Probably due to network connectivity break when fetching packages from the internet. Re-run the script.
- Script stops for more than 10 minutes -  Terminate the script (Ctrl+C) and make sure proxy is configured correctly. After that you may safely re-run this failing script again.

# 8. Troubleshooting

* Some script step failed

  If, for some reason, any shell script fails at some step, you can safely run that script again.
* Script stops/freezes when fetching packages
  
  Make sure the proxy is configured properly in the operating system, according to Section 6.2 of this guide (Proxy Setup). If the problem still persists, run the ` yum clean all` command as root user and run the shell script again.
  
* Connectivity issues
  - If a script cannot fetch packages from the internet and ends with error message, make sure no firewall blocks connections to the external services on the internet on TCP port `21,80,443` and UDP `53` or Proxy ports
  
  - Commands print error about missing `urllib3` package. Reinstall this package as follows and run failing Ansible script again.
    ```
    # pip uninstall -y urllib3`
    # pip install urllib3
    ```
  
* Log files
  - Each run of a script produces a log file in repository `./scripts/ansible/logs` subfolder. It contains the same output as the operator received on the console when running the automation script.

# 9. Changelog
| Ver   | Date       | Changes                              |
|-------|------------|--------------------------------------|
| 0.1   | June 2019  | First revision                       |
| 0.2   | June 2019  | Added info about available log files |
