# Sigma-and-Sysmon


Download or clone Sigma repository:  https://github.com/SigmaHQ/sigma  
Install python: https://www.python.org/downloads/   
Install Sigma's dependencies: Sigma requires several Python packages to run correctly: `pip install -r requirements.txt`  
Test if all ok: `python sigmac --version`  


`Invoke-WebRequest -Uri https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml -OutFile C:\Windows\config.xml`

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


Download sysmon: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon  
Install sysmon config file: https://github.com/Neo23x0/sysmon-config/blob/master/sysmonconfig-export-block.xml  
Install first time - Run with administrator rights `sysmon.exe -accepteula -i sysmonconfig-export.xml`   
Or add it into existing Sysmon configuration `sysmon -c sysmonconfig-export.xml`

## Suricata (Instead of Snort)
Download https://suricata.io/download/  

## Wazuh (Instead of OSSEC) server instals on Linux, agent can be win or unix
https://documentation.wazuh.com/current/installation-guide/index.html  

## Snort  

Install Snort 	https://www.snort.org/downloads  
Install npcap   https://npcap.com/#download  










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



  
  
  
  
  
  
  
  
  
  
  
  
  
  
  



