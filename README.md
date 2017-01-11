# Malicious Macro Bot
Project to provide classification, family identification, and other insights into potentially malicious Microsoft Office documents.
<br>
### Basic Example Usage:
```
import mmbot as mmb
mymacrobot = mmb.MaliciousMacroBot(benign_path='./model/benign_samples/',
                                   malicious_path='./model/malicious_samples/',
                                   model_path='./model/')
mymacrobot.mmb_init_model()
pathtofile = '/home/jschmo/malware_research/rsa/samples/unknown/mydoc.docm'
result = mymacrobot.mmb_predict(pathtofile, datatype='filepath')
print result.iloc[0]
```
<br>
You can get the results in a summarized json format using an mmb_prediction_to_json helper function.  This will return a string in json format that can be used in other systems like elastic search<br>
`mymacrobot.mmb_prediction_to_json(result)`
<br>
<br>
### Installation
There are a number of dependencies to install.  Unzip model.zip into the same directory as mmbot.py or put it elsewhere and specify the directory paths when instantiating a MaliciousMacroBot object.

