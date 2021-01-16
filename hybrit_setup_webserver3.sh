#!/bin/bash

set -ex

moodle_on_azure_configs_json_path=${1}

. ./nginx_helper.sh
. ./php_helper.sh
. ./common_helper.sh
. ./varnish_helper.sh

get_setup_params_from_configs_json $moodle_on_azure_configs_json_path || exit 99

sudo echo $siteFQDN >> /tmp/vars.txt
sudo echo $syslogServer >> /tmp/vars.txt
sudo echo $webServerType >> /tmp/vars.txt
sudo echo $dbServerType >> /tmp/vars.txt
sudo echo $fileServerType >> /tmp/vars.txt
sudo echo $nfsVmName >> /tmp/vars.txt
sudo echo $nfsByoIpExportPath >> /tmp/vars.txt
sudo echo $htmlLocalCopySwitch >> /tmp/vars.txt
sudo echo $phpVersion          >> /tmp/vars.txt

#Done 1

#Start Of Installations
install_nginx

install_php $phpVersion

install_varnish

#End Of Installations

#Start Of Configurations

	#Start Of PHP Configuration
	configure_php_conf $phpVersion
        configure_fpm $phpVersion
	#End Of PHP Configuration
	
	#Start Of Nginx Configuration
	configure_main_nginx_conf

        #mount nfs
        configure_nfs_client_and_mount $nfsVmName /moodle /moodle

	# Set up html dir local copy if specified
	setup_html_dir
	
        
	configure_moodle_nginx_conf $siteFQDN

	# Remove the default site. Moodle is the only site we want
        remove_default_site
   
        setup_moodle_mount_dependency_for_systemd_service nginx || exit 1
        
        configure_varnish
        
	#End Of Nginx Configuration

exit 99

#End Of Configurations
