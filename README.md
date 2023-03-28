# Sigma-and-Sysmon


Download or clone Sigma repository:  https://github.com/SigmaHQ/sigma  
Install python: https://www.python.org/downloads/   
Install Sigma's dependencies: Sigma requires several Python packages to run correctly: `pip install -r requirements.txt`  
Test if all ok: `python sigmac --version`  


 

It contains the rule base in the folder “./rules” and the Sigma rule compiler “./tools/sigmac”  
How to change Sigma rule https://www.nextron-systems.com/2018/02/10/write-sigma-rules/  



sigmac -t sysmon -c <sigma_rule_file.yml> > <sysmon_config_file.xml>  

We open the results for “Quarks PWDump“, a password dumper often used by Chinese threat groups. It creates temporary files that we want to detect in our SysInternals Sysmon log data.
So, what we do is to find a Sigma rule in the repository that we can use as a template for our new rule. We use the ‘search’ function to find a rule that looks for “File Creation” events (EventID 11) in Sysmon log data.

sigmac -t sysmon -c <sigma_rule_file.yml> > <sysmon_config_file.xml>
Replace <sigma_rule_file.yml> with the name of your Sigma rule file, and <sysmon_config_file.xml> with the name you want to give to the Sysmon configuration file.

Once the Sysmon configuration file is created, you can load it into Sysmon by running the following command:
php
Copy code
sysmon -c <sysmon_config_file.xml>
This will load the Sysmon configuration file and start monitoring for the specified events.

https://medium.com/@olafhartong/sysmon-14-0-fileblockexecutable-13d7ba3dff3e
https://medium.com/@olafhartong/sysmon-14-0-fileblockexecutable-13d7ba3dff3e


# Create Sysmon directory
New-Item -ItemType Directory -Path "C:\Sysmon"
# Download Sysmon
Invoke-WebRequest "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "C:\Sysmon\Sysmon.zip"
# Extract Sysmon
Expand-Archive "C:\Sysmon\Sysmon.zip" -DestinationPath "C:\Sysmon"
# Download Sysmon config
Invoke-WebRequest "https://raw.githubusercontent.com/Neo23x0/sysmon-config/master/sysmonconfig-export-block.xml" -OutFile "C:\Sysmon\sysmonconfig-export-block.xml"
# Install Sysmon as a service
& "C:\Sysmon\Sysmon.exe" -accepteula -i "C:\Sysmon\sysmonconfig-export-block.xml"
# Start Sysmon service
Start-Service -Name Sysmon












`sysmon64.exe –accepteula –i c:\windows\config.xml`   

* `sysmon -c` shows info about sysmon  


Creating a separate folder for Sysinternals tools and setting appropriate permissions to restrict access to authorized users only.
Using a network share with access control lists (ACLs) that limit access to authorized users or groups.  

------------------   
To use AccessChk, you need to open a command prompt and run the AccessChk command with the appropriate parameters. Here are some examples:

To check the permissions of a specific file:

accesschk.exe -s -d c:\path\to\file.txt

To check the permissions of a specific user or group across multiple files and folders:

accesschk.exe -u username c:\path\to\folder

To check the effective permissions of a user or group on a specific file or folder:

accesschk.exe -e -u username c:\path\to\folder

To list all files and folders that a user or group has access to:

accesschk.exe -w -u username c:\

AccessChk provides detailed output that shows the permissions that are set on each resource, including the user or group that has access and the type of access (such as read, write, or execute). It can also generate reports in various formats, including CSV, XML, and text.

AccessChk is a powerful tool that requires some technical expertise to use effectively. It should be used with caution and only by experienced users who understand the potential risks and limitations of permission analysis tools.  
--------------------------  



Install first time - Run with administrator rights 	`sysmon.exe -accepteula -i -c sysmonconfig-export.xml`   
Or add it into existing Sysmon configuration 		`sysmon -c sysmonconfig-export.xml`

## Suricata (Instead of Snort)
Download https://suricata.io/download/  

## Wazuh (Instead of OSSEC) server instals on Linux, agent can be win or unix
https://documentation.wazuh.com/current/installation-guide/index.html  

## Snort    		https://zaeemjaved10.medium.com/installing-configuring-snort-2-9-17-on-windows-10-26f73e342780

Install Snort 	https://www.snort.org/downloads  
Install npcap   https://npcap.com/#download  

Download latest Snort rules     https://www.snort.org/downloads/#rule-downloads   
Download latest Rules and copy to Snort folder  

etc/snort.conf   configure:  
	ipvar 10.11.10.1/24 any
	var RULE_PATH ../rules  
	var SO_RULE_PATH ../so_rules  
	var PREPROC_RULE_PATH ../preproc_rules  
	var WHITE_LIST_PATH ../rules  
	var BLACK_LIST_PATH ../rules same path as /rules before  
	182 config logdir: C:\Snort\log  
	dynamicpreprocessor directory C:\Snort\lib\snort_dynamicpreprocessor  
	dynamicengine C:\Snort\lib\snort_dynamicengine\sf_engine.dll  
	
	COMMENT OUT THESE:  
	#dynamicdetection directory /usr/local/lib/snort_dynamicrules  
	#preprocessor normalize_ip4  
	#preprocessor normalize_tcp: block, rsv, pad, urp, req_urg, req_pay, req_urp, ips, ecn stream  
	#preprocessor normalize_icmp4  
	#preprocessor normalize_ip6  
	#preprocessor normalize_icmp6  
	
	"whitelist $WHITE_LIST_PATH/white_list.rules, \		change to "...ATH/white_list, \"
	"blacklist $BLACK_LIST_PATH/black_list.rules" 		change to "..._PATH/black_list"  
	
	Converted back slashes to forward slashes in lines":  
	"# site specific rules  
	include $RULE_PATH/local.rules  
	include $RULE_PATH\app-detect.rules  
	include $RULE_PATH\attack-responses.rules  
	include $RULE_PATH\backdoor.rules  
	include $RULE_PATH\bad-traffic.rules"  
	
	






## Elastic Stack: (Elasticsearch, Logstash, and Kibana) 
https://www.elastic.co/downloads/elasticsearch  
https://www.elastic.co/downloads/kibana  
https://www.elastic.co/downloads/logstash   
`reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem" /v LongPathsEnabled /t REG_DWORD /d 1 /f`  
`Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Value 1`  

`taskkill /f /im explorer.exe & start explorer.exe`

https://www.youtube.com/watch?v=BybAetckH88


`elasticsearch-reset-password -u kibana_system`


https://www.elastic.co/guide/en/elasticsearch/reference/current/zip-windows.html  
1.) elasticsearch\config\elasticsearch.yml file, inside copy:  
`action.auto_create_index: .monitoring*,.watches,.triggered_watches,.watcher-history*,.ml*`   
2.) Next open cmd - `\elasticsearch-8.6.2\bin>elasticsearch.bat` launch bat file and wait for line "Elasticsearch security features have been automatically configured!" Save 256hash, password and token.  
3.) Copy to config/elasticsearch.yml data from cmd bat output into .yml file:  
xpack.security.http.ssl:
  enabled: false  
xpack.security.transport.ssl:
  enabled: false  
4.)Launch elasticsearch.bat again - it will launch web server now. To connect use localhost:9200. User: `elastic` , password from first .bat run.  
------------------  KIBANA --------------  
1.) elasticsearch-8.6.2\bin> `elasticsearch-reset-password -u kibana_system`  
2.) kibana/config/kibana.yml:  
  Uncomment:  
  server.port: 5601  
  server.host: "localhost"  
  elasticsearch.hosts: ["http://localhost:9200"]  
  elasticsearch.username: "kibana_system"  
  elasticsearch.password: "pass"  copy generated pass  
3.) Launch \kibana-8.6.2\bin>kibana.bat  
----------------- LOGSTASH ---------------  
1.) in logstash/bin create new "learn.config"  
input {
	stdin {
	}	
}
output {
	stoutput {
		codec => rubydebug
	}
	elasticsearch {
	hosts => ["http://localhost:9200"]
	index => "test.logstash"
	user => "elastic"
	password => "b9oeeFKv9ZBqn0S1oLK-"
	}
}   



  
  
  
  
  
  
  
  
  
  
  
  
  
  
  



