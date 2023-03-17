# Sigma-and-Sysmon

Download or clone Sigma repository  https://github.com/SigmaHQ/sigma
It contains the rule base in the folder “./rules” and the Sigma rule compiler “./tools/sigmac”.   
How to change Sigma rule https://www.nextron-systems.com/2018/02/10/write-sigma-rules/  


1.) Sigma converter tool to convert the Sigma rule to a Sysmon configuration file in XML format. You can use the following command to convert the rule:  
sigmac -t sysmon -c <sigma_rule_file.yml> > <sysmon_config_file.xml>  

We open the results for “Quarks PWDump“, a password dumper often used by Chinese threat groups. It creates temporary files that we want to detect in our SysInternals Sysmon log data.
So, what we do is to find a Sigma rule in the repository that we can use as a template for our new rule. We use the ‘search’ function to find a rule that looks for “File Creation” events (EventID 11) in Sysmon log data.
