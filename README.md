# Malicious Macro Bot
Project to provide classification, family identification, and other insights into potentially malicious Microsoft Office documents.
<br>
### Basic Example Usage:
import mmbot as mmb<br>
mymacrobot = mmb.MaliciousMacroBot(benign_path='./model/benign_samples/',<br>
                                   malicious_path='./model/malicious_samples/',<br>
                                   model_path='./model/')<br>
mymacrobot.mmb_init_model()<br>
pathtofile = '/home/jschmo/malware_research/rsa/samples/unknown/mydoc.docm'<br>
result = mymacrobot.mmb_predict(pathtofile, datatype='filepath')<br>
print result.iloc[0]<br>
<br>
<br>
### Installation
There are a number of dependencies to install.  Unzip model.zip into the same directory as mmbot.py or put it elsewhere and specify the directory paths when instantiating a MaliciousMacroBot object.

