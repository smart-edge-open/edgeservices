```text
Copyright 2019 Smart-Edge.com, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
# Build server setup - automation scripts

The purpose of the scripts available in this folder is to automate the process of build server setup, its services configuration, binaries compilation and in general - automate most common manual operations operator would have to carry out manually step by step when setting up build server.

Scripts available here will download needed packages from defined repositories, resolve dependencies, configure services,
build binaries or build Docker images. Instead of running separate commands, operator will run only two specific scripts.
The scripts invoke commands from yaml files that are then processed by Ansible automation platform.
Make sure to read given NOTES below and troubleshooting section.

### Prerequisites
Before running any script provided, please make sure that the following requirements are already met:
- server is running CentOS 7.5 18.10 release (minimal install is fine; no GUI is needed)
- connection to the internet is available (mostly TCP ports 80 and 443)
- if proxy is used, make sure that it is set up correctly before running any further scripts (see chapter 3.)
- operating system software is up to date (run yum update before running any script)
- root account is required (each script requires root permissions)
- server terminal console access or remote ssh access is needed (only on of them)

### Proxy setup
If the server is not using proxy to to access the internet, please skip this chapter.
If proxy is used, please follow below steps to configure both operating system and services that will be ran later by
automation scripts.
Example configurations of proxy for each service or operating system component are available for preview in subfolder ``` ./examples/proxy```.
Their structure reflect the real one in your operating system. 
It is advised to not copy them directly to your operating system but instead, modify your own ones to contain items
available in those example files.

##### OS setup files:
* /etc/environment
   Make sure that your current environment file contains variables for http_proxy and HTTP_PROXY and if https proxy is 
   also used, then also include https_proxy and HTTPS_PROXY in your config file. Additionally, include ftp_proxy and FTP_PROXY variables with correct IP and port addresses.
   See example in provided file in folder: `../examples/proxy/etc/environment`
* /etc/yum.conf
   Add one line for http proxy to your yum.conf file as shown in `../examples/proxy/etc/yum.conf`
   > Tip: Make sure the port is correct and slash sign (/) is present at the end of the line.
##### Docker service
* `/etc/systemd/system/docker.service.d/http_proxy.conf`
   Example configuration for docker service is inside file `../examples/proxy/systemd/system/docker.service.d/http_proxy.conf`
   If you do not have Docker configured and this file is missing in /etc folder, you may copy example this file to given path in
   /etc folder and modify it according to your needs.
* `/root/.docker/config.json`
   Example configuration is inside file `../examples/proxy/root/.docker/config.json`
   
> Tip: Once proxy setup is complete, it is advised to reboot server or at least log out and log in again, so that at least
`/etc/environment` will be read by login service and shell startup scripts.

> Tip: If you are not sure whether your proxy settings work, you may run a simple `yum update` command to check whether 
the internet is reachable with given proxy settings. DO NOT install or upgrade any packet yet manually.

### Scripts for build server
The following automation scripts are available to operator. 
For build server in `./build_server` subfolder:
  - `01_setup_server.sh`
  - `02_build_images.sh`
> Tip: All of them need to be run in correct order as instructed below.

#####  01_setup_server.sh
This is the first script that operator needs to run.
Root permissions are needed and it's advised to run it directly from root account (not via sudo).
Script will then:
  - add EPEL repository to yum packet management system
  - install required rpm packages for build process
  - install services (including Docker CE)
  - install RT kernel
  - modify grub configuration
  - disable yum plugins

>  NOTE:
  All docker images and containers that are present on the server will be removed.
  NOTE:
  Please do not rebuild grub configuration file or edit it manually (`/boot/grub2/grub.cfg`).

##### Run script:
  * Log in as root user or switch to user account with command:
    ```     
    $ su -
    ```
  * Run first script
    ```
    ./01_setup_server.sh
    ```
  * Watch for possible errors and fix them once they appear and script execution is stopped.
  * Wait till all steps complete.
  * Reboot server when requested, so that it will boot with RT kernel:
    ```
    # reboot
    ```
  * There is no need to select kernel at in grub, as the newly installed RT will be picked up.
  * Run first script again 
    ```
    ./01_setup_server.sh
    ```
  * This time, additional packages will be installed, along with GO language and Docker CE.
     
    >  NOTE: Any previously build Docker images/containers will be removed without any warning.

  * Once required operations complete, this script job is done.
  * Now you are ready to run a second script called: 02_build_images.sh

##### 02_build_images.sh
This is the second script that operator needs to run on build machine (node).
Root permissions are needed and it's advised to run script directly from root account (not via sudo).
It's purpose is to:
- remove all previous Docker images and containers (if present)
- build new application binaries
- build new Docker images for the following components:
    * appliance
    * edgednssvr
- export Docker images to filesystem

##### Run script:
  * Log in as root user or switch to user account with command:
    ```
    $ su -
    ```
  * Run script
    ```
    ./02_build_images.sh
    ```
  * Watch for possible errors and fix them once they appear and script execution is stopped.
  * Wait till all steps complete.
  * Once complete, script job is done.
  * Binaries of above components and images are now stored in the following location:
     ```<repo_location>/appliance-ce/dist/```

### Troubleshooting
* Some step failed
  If - for some reason - any shell script fails at some step, you can safely run it again.
* Script stops/freezes at fetching packages
  Make sure proxy is configured properly in operating system, according to guide provided above.
  if problem still persists, run the following command as root user and rerun shell script again.
  ```
   # yum clean all
   ```
* Build step fails
  Some fetched packets might get corrupted - remove the following folders:
  ```
  # rm -rf /root/go
  ```
