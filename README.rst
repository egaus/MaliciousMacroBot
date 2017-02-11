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
There are only four lines of code needed to get your first prediction on a macro-enabled file.

1. Import the MaliciousMacroBot class

``from mmbot import MaliciousMacroBot``


2. Instantiate the class

``mmb = MaliciousMacroBot()``


3. Make a prediction

Note: mmb_predict() returns a Pandas DataFrame.  If you are unfamiliar with Pandas DataFrames, there is a helper function that can be used to convert a useful summary of the prediction result to json.

``prediction = mmb.mmb_predict('./your_path/your_file.xlsm', datatype='filepath')``


4. (Optional) Convert result from Pandas DataFrame to json

``print mmb.mmb_prediction_to_json(prediction)``


This Python package was designed to give flexibility of options to those who want to use it.  The mmb_predict() function will take in single office documents as a path to the specific file, or as a path to a directory and recursively analyze all files in the path and subdirectories, or as a raw byte stream of a file passed to it, or as a string of already extracted vba text that some other tool already processed.  Finally, all of these options can be done in bulk mode, where the input is a Pandas DataFrame.  The method will decide how to handle it based on the "datatype" argument and the actual python object type passed in.


More Information
----------------
Python 3 not fully supported.  One package dependency is not working in Python 3.5 and higher, but once that is updated the rest of this project is ready to support Python 3.


License
-------
* Free software: MIT License 
* Documentation: https://mmbot.readthedocs.io.

