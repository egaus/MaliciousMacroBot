Malicious Macro Bot Project
===========================

The main goals of this project are to:
* Provide a powerful malicious file triage tool for cyber responders.
* Help fill existing detection gaps for malicious office documents, which are still a very prevalent attack vector today.
* Deliver a new avenue for threat intelligence, a way to group similar malicious office documents together to identify phishing campaigns and track use of specific malicious document templates.

These goals are achieved through clever feature engineering and applied machine learning techniques like Random Forest and TF-IDF.

----

Installation
------------
``sudo pip install mmbot``

That's it!  Otherwise checkout the source on this git repo.


Usage Examples
--------------
**Triage office files with five lines of code**

Import, instantiate, predict::

	from mmbot import MaliciousMacroBot
	mmb = MaliciousMacroBot()
        mmb.mmb_init_model()
	result = mmb.mmb_predict('./your_path/your_file.xlsm', datatype='filepath')
	print result.iloc[0]

Note: mmb_predict() returns a Pandas DataFrame.  If you are unfamiliar with Pandas DataFrames, there is a helper function that can be used to convert a useful summary of the prediction result to json.

**Convert result from Pandas DataFrame to json**

``print mmb.mmb_prediction_to_json(prediction)``


This package was designed for flexibility.  The mmb_predict() function will take in single office documents as a path to the specific file, as a path to a directory and recursively analyze all files in the path and subdirectories, as a raw byte stream of a file passed to it, or as a string of already extracted vba text that a different tool already processed.  Finally, all of these options can be done in bulk mode, where the input is a Pandas DataFrame.  The method will decide how to handle it based on the "datatype" argument and the actual python object type passed in.


More Information
----------------
Python 3 not fully supported.  One package dependency is not working in Python 3.5 and higher, but once that is updated the rest of this project is ready to support Python 3.


License
-------
* Free software: MIT License 
* Documentation: https://maliciousmacrobot.readthedocs.io.

