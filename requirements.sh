#!/usr/bin/env bash

##--------------------------------------------------------------------
## Copyright (c) 2019 Dianomic Systems
##
## Licensed under the Apache License, Version 2.0 (the "License");
## you may not use this file except in compliance with the License.
## You may obtain a copy of the License at
##
##     http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.
##--------------------------------------------------------------------

##
## Author: Mark Riddoch
##

fledge_location=`pwd`
os_name=`(grep -o '^NAME=.*' /etc/os-release | cut -f2 -d\" | sed 's/"//g')`
os_version=`(grep -o '^VERSION_ID=.*' /etc/os-release | cut -f2 -d\" | sed 's/"//g')`
echo "Platform is ${os_name}, Version: ${os_version}"

if [[ ( $os_name == *"Red Hat"* || $os_name == *"CentOS"* ) &&  $os_version == *"7"* ]]; then
	echo Installing development tools 7 components
	sudo yum install -y yum-utils
	sudo yum-config-manager --enable rhel-server-rhscl-7-rpms
	sudo yum install -y devtoolset-7
	echo Installing boost components
	sudo yum install -y boost-filesystem
	sudo yum install -y boost-program-options
	source scl_source enable devtoolset-7
	export CC=/opt/rh/devtoolset-7/root/usr/bin/gcc
	export CXX=/opt/rh/devtoolset-7/root/usr/bin/g++
elif apt --version 2>/dev/null; then
	echo Installing boost components
	sudo apt install -y libboost-filesystem-dev
	sudo apt install -y libboost-program-options-dev
else
	echo "Requirements cannot be automatically installed, please refer README.rst to install requirements manually"
fi

if [ $# -eq 1 ]; then
	directory=$1
	if [ ! -d $directory ]; then
		mkdir -p $directory
	fi
else
	directory=~
fi

if [ ! -d $directory/lib60870 ]; then
	cd $directory
	echo Fetching MZA lib60870 library
	git clone https://github.com/mz-automation/lib60870.git
	cd lib60870/lib60870-C
	mkdir build
	cd build
	cmake ..
	make
	cd ..
	echo Set the environment variable LIB_104 to `pwd`
	echo export LIB_104=`pwd`
fi
