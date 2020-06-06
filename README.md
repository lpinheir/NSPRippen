# NSP_CVE_POL
This is a simple script to collect "IPS Policy" and "Attack Repository" data from McAfee Network Security Platform to be used in Analytics Solutions.

Please, run the script in the following order:

1 - cvs_nsp_list_PolicyID - 
Run this script to collect your IPS Policies IDs to be used in the next Script.

2 - cvs_nsp_JSONGen_Attacks - 
Run this script to collect your information about all attacks that are included in your IPS Policy Master Repository (This extraction cover CVE also).

3 - cvs_nsp_JSONGen_Policies - 
Run this script to collect your IPS Policies contents based on your extracted Policy IDs (Collected in 1 - cvs_nsp_list_PolicyID).

You can use those JSON files to feed some Analytics Solution

