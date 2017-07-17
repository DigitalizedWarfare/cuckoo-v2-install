Cuckoo V2 – The Saga Continues.
So to celebrate that its defcon time once again I have decided to revamp the cuckoo malware lab. There are more and more people wanting to get into malware analysis every day. So I have updated the lab and grabbed some fun payloads to run. 
You are going to need the following to run this correctly.

1.	VMWare Workstation : to run the cuckoo vm
2.	Ubuntu Server 15 x86: to hold cuckoo install.
3.	Windows : to run malware on
4.	Malware : This is a malware lab

When installing the Ubuntu vm create a user called “maint”. This is the user that all scripts will run in, as well as the user account for cuckoo. I have also included sample conf files. Feel free to use them. Just change ip’s and what not.
Get script from my Git Repo: https://github.com/DigitalizedWarfare/cuckoo-v2-install.git
After you have ran the script and created the cuckoo user, you will need to run the following in the user’s virtual env. (Execute: . venv/bin/activate) 

1.	git clone https://github.com/VirusTotal/yara.git
2.	cd yara
3.	./bootstrap.sh
4.	./configure --prefix=${VIRTUAL_ENV} && make && make install
5.	pip install python-yara
Then, install volatility:
1.	git clone https://github.com/volatilityfoundation/volatility.git
2.	cd volatility/ 
3.	pip install distorm3 pycrypto pillow openpyxl ujson
4.	python ./setup.py install

A few things to understand about this script. It just sets up the os for you. Any configuring or vm creation is not done here. 
This is done by you. So after the script runs, create vm’s any way you want with whatever software you want. For my labs I am using WinXPSP3x86 and Win7SP0x86.
 
Here is the best link or article that I want you to use for information on cuckoo setup. The new version of cuckoo does not follow these exact steps but I want you to have a general overview of the process. 
https://infosecspeakeasy.org/t/howto-build-a-cuckoo-sandbox/27
Also install the guest packages from the link above.
Pay attention to the applications you install. Disable any update settings, bump down security on browsers, and turn off firewall and other system level setting.

Http://oldapps.com

Here is the documentation on creating the vms.

http://docs.cuckoosandbox.org/en/latest/installation/guest/

Do not forget to set the ip address information of the vm. This information will need to be placed inside the virtualbox.conf file. You can use the 192.168.56.1 address for dns or google (8.8.8.8).

The last step when creating a vm, is making a snapshot. This is the point where cuckoo will start processing malware. Each time cuckoo needs to process a piece of malware, it restores this point.

Also you need to set the osprofile for each vm in the virtualbox.conf file. You can get the profile name by using the vol.py –info command. This name has to match the OS you are running. Example: My win xp is WinXPSP3x86 for the OS build. The osprofile setting has to be this exact string. And yes treat it as Case sensitive.

When you’re ready to run cuckoo you can execute the following 3 commands. If you do not have screen installed, you need to remove it from the commands below. The Rooter has to be started first and left running. The then report server. Change its ip to what your vm is. And finally cuckoo needs to be started.

•	screen cuckoo rooter -g maint --sudo
•	screen cuckoo web runserver 172.16.1.29:5000
•	screen cuckoo -d

https://www.proteansec.com/linux/installing-using-cuckoo-malware-analysis-sandbox/
https://media.readthedocs.org/pdf/cuckoo/latest/cuckoo.pdf

