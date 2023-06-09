### SYSMON

# Create Sysmon directory
Write-Host "Creating Sysmon directory..."
New-Item -ItemType Directory -Path "C:\Sysinternals"
# Download Sysmon
Write-Host "Downloading Sysmon..."
Invoke-WebRequest "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "C:\Sysinternals\Sysmon.zip"
# Extract Sysmon
Write-Host "Extracting Sysmon..."
Expand-Archive "C:\Sysinternals\Sysmon.zip" -DestinationPath "C:\Sysinternals" -Force 
# Download Sysmon config for Neo23, alternatives SwiftOnSecurity and olafhartong
Write-Host "Downloading Sysmon config..."
Invoke-WebRequest "https://raw.githubusercontent.com/Neo23x0/sysmon-config/master/sysmonconfig-export-block.xml" -OutFile "C:\Sysinternals\sysmonconfig-export-block.xml"
# Install Sysmon as a service
Write-Host "Installing Sysmon as a service..."
& "C:\Sysinternals\Sysmon.exe" -accepteula -i "C:\Sysinternals\sysmonconfig-export-block.xml"
# Start Sysmon service
Write-Host "Starting Sysmon service..."
Start-Service -Name Sysmon
#sysmon -c #shows info about sysmon

### AUTORUNS

# Download Sysinternals Autoruns
Write-Host "Downloading Sysinternals Autoruns..."
Invoke-WebRequest "https://download.sysinternals.com/files/Autoruns.zip" -OutFile "C:\Sysinternals\Autoruns.zip"
# Extract Sysinternals Autoruns
Write-Host "Extracting Sysinternals Autoruns..."
Expand-Archive "C:\Sysinternals\Autoruns.zip" -DestinationPath "C:\Sysinternals" -Force
# Add Sysinternals path to environment variable
Write-Host "Adding Sysinternals directory path to environment variable..."
$env:Path += ";$env:C:\Sysinternals"

### TCPView

# Download Sysinternals TCPView
Write-Host "Downloading Sysinternals TCPView..."
Invoke-WebRequest "https://download.sysinternals.com/files/TCPView.zip" -OutFile "C:\Sysinternals\TCPView.zip"
# Extract Sysinternals TCPView.zip
Write-Host "Extracting Sysinternals TCPView..."
Expand-Archive "C:\Sysinternals\TCPView.zip" -DestinationPath "C:\Sysinternals" -Force

### ProcessMonitor

# Download Sysinternals ProcessMonitor
Write-Host "Downloading Sysinternals ProcessMonitor..."
Invoke-WebRequest "https://download.sysinternals.com/files/ProcessMonitor.zip" -OutFile "C:\Sysinternals\ProcessMonitor.zip"
# Extract Sysinternals ProcessMonitor.zip
Write-Host "Extracting Sysinternals ProcessMonitor..."
Expand-Archive "C:\Sysinternals\ProcessMonitor.zip" -DestinationPath "C:\Sysinternals" -Force

### AccessEnum and ShareEnum

# Download Sysinternals AccessEnum and ShareEnum
Write-Host "Downloading Sysinternals AccessEnum and ShareEnum..."
Invoke-WebRequest "https://download.sysinternals.com/files/AccessEnum.zip" -OutFile "C:\Sysinternals\AccessEnum.zip"
Invoke-WebRequest "https://download.sysinternals.com/files/ShareEnum.zip" -OutFile "C:\Sysinternals\ShareEnum.zip"
# Extract Sysinternals AccessEnum.zip and ShareEnum.zip
Write-Host "Extracting Sysinternals AccessEnum and ShareEnum..."
Expand-Archive "C:\Sysinternals\AccessEnum.zip" -DestinationPath "C:\Sysinternals" -Force
Expand-Archive "C:\Sysinternals\ShareEnum.zip" -DestinationPath "C:\Sysinternals" -Force


----------------------------------------------------------------------------------------------------------------------------------------------------------

SNORT

## Snort    		https://zaeemjaved10.medium.com/installing-configuring-snort-2-9-17-on-windows-10-26f73e342780

Install Snort 	https://www.snort.org/downloads  
Install npcap   https://npcap.com/#download  

Download latest Snort rules     https://www.snort.org/downloads/#rule-downloads   
Download latest Rules and copy to Snort folder  

$env:PATH += ";C:\Snort"

> snort -i 1 -c C:\Snort\etc\snort.conf -T
> Get-NetAdapter
> snort.exe -W
> netstat -aon # which processes are using which network connections
> Start-Process -FilePath "C:\Snort\bin\snort.exe" -ArgumentList "-c C:\Snort\etc\snort.conf -i 1" -NoNewWindow

-------------------
cd C:\Snort\bin
start /B snort.exe -i 1 -c C:\Snort\etc\snort.conf -A console



Save the file with a .bat extension, for example "start-snort.bat".

Press the Windows key + R to open the Run dialog box.

Type "shell:startup" and press Enter. This will open the Startup folder.

Right-click in the folder and select "New" > "Shortcut".

Browse to the location of the batch script you created earlier, select it, and click "Next".

Give the shortcut a name, for example "Start Snort".

Click "Finish" to create the shortcut.
------------------


WINDOWS TASK SCHEDULER

Yes, Windows has a built-in task scheduler that allows you to schedule tasks to run automatically at specific times or events. This is similar to the Linux cron job scheduler. You can use the Windows Task Scheduler to run a variety of tasks, such as running scripts, launching programs, sending emails, and more.

To access the Task Scheduler in Windows, you can use the following steps:

Open the Start menu and search for "Task Scheduler" or open the Control Panel and click on "Administrative Tools" > "Task Scheduler".
Click on "Create Basic Task" or "Create Task" to create a new task.
Follow the prompts to set up the task, including setting the trigger (when the task should run) and the action (what the task should do).
Save and test the task to ensure it runs correctly.
You can also use command-line tools like schtasks.exe to create and manage tasks, which can be useful for scripting and automation.

---------------------
YARA 

#Download latest Yara https://github.com/VirusTotal/yara/releases/latest


# Change directory to Downloads folder
cd $HOME\Downloads
# Find the path of the YARA zip file that begins with "yara" and ends with "win64.zip"
$zipPath = Get-ChildItem -Path . -Filter "yara*win64.zip" | Select-Object -ExpandProperty FullName
# Create a new directory for YARA
New-Item -ItemType Directory -Path C:\Yara
# Extract the YARA zip file to the YARA directory
Expand-Archive -Path $zipPath -DestinationPath C:\Yara
# Move the YARA executables to the YARA directory
Move-Item -Path C:\Yara\yara64.exe -Destination C:\Yara
Move-Item -Path C:\Yara\yarac64.exe -Destination C:\Yara


















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

## Suricata (Instead of Snort)
Download https://suricata.io/download/ 

https://www.freecodecamp.org/news/home-network-security-with-suricata-raspberrypi4-python/



## Wazuh (Instead of OSSEC) server instals on Linux, agent can be win or unix
https://documentation.wazuh.com/current/installation-guide/index.html  

 
	
	






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
