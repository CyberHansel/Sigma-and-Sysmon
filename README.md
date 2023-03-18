# Sigma-and-Sysmon


Download or clone Sigma repository:  https://github.com/SigmaHQ/sigma
Install python: https://www.python.org/downloads/ 
Install Sigma's dependencies: Sigma requires several Python packages to run correctly: pip install -r requirements.txt
Test if all ok: python sigmac --version


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

https://github.com/Neo23x0/sysmon-config/blob/master/sysmonconfig-export-block.xm
