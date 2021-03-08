import os
#get the current code files directory and change the working dir
dir_path = os.path.dirname(os.path.realpath(__file__))
os.chdir(dir_path)


#config file for shared variables

Malware_tag = './malware'
Malware_dir = 'malware/'
Benign_dir = 'benign/'
Decision = 'Decision'