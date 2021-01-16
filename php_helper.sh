#!/bin/bash

function install_php
{
	local phpVersion=${1}
	
	sudo apt-get install -y software-properties-common
	sudo add-apt-repository ppa:ondrej/php -y
	sudo apt update
	
	sudo apt install -y php$phpVersion-fpm php$phpVersion-common php$phpVersion-mysql php$phpVersion-gmp php$phpVersion-curl php$phpVersion-intl php$phpVersion-mbstring php$phpVersion-soap php$phpVersion-xmlrpc php$phpVersion-gd php$phpVersion-xml php$phpVersion-cli php$phpVersion-zip
}

function configure_php_conf
{
	local phpVersion=${1}

	PhpIni=/etc/php/$phpVersion/fpm/php.ini

	sudo sed -i "s/memory_limit.*/memory_limit = 512M/" $PhpIni
	sudo sed -i "s/max_execution_time.*/max_execution_time = 18000/" $PhpIni
	sudo sed -i "s/max_input_vars.*/max_input_vars = 100000/" $PhpIni
	sudo sed -i "s/max_input_time.*/max_input_time = 600/" $PhpIni
	sudo sed -i "s/upload_max_filesize.*/upload_max_filesize = 1024M/" $PhpIni
	sudo sed -i "s/post_max_size.*/post_max_size = 1056M/" $PhpIni
	sudo sed -i "s/;opcache.use_cwd.*/opcache.use_cwd = 1/" $PhpIni
	sudo sed -i "s/;opcache.validate_timestamps.*/opcache.validate_timestamps = 1/" $PhpIni
	sudo sed -i "s/;opcache.save_comments.*/opcache.save_comments = 1/" $PhpIni
	sudo sed -i "s/;opcache.enable_file_override.*/opcache.enable_file_override = 0/" $PhpIni
	sudo sed -i "s/;opcache.enable.*/opcache.enable = 1/" $PhpIni
	sudo sed -i "s/;opcache.memory_consumption.*/opcache.memory_consumption = 256/" $PhpIni
	sudo sed -i "s/;opcache.max_accelerated_files.*/opcache.max_accelerated_files = 8000/" $PhpIni
}

function configure_fpm
{
	local phpVersion=${1}
	cat <<EOF > /etc/php/$phpVersion/fpm/pool.d/www.conf
[www]
user = www-data
group = www-data
listen = /run/php/php$phpVersion-fpm.sock
listen.owner = www-data
listen.group = www-data
pm = dynamic
pm.max_children = 3000 
pm.start_servers = 20 
pm.min_spare_servers = 20 
pm.max_spare_servers = 30 
EOF

     # Restart fpm
     service php$phpVersion-fpm restart
}