#! /usr/bin/env python

from os import listdir
from os.path import isfile, join
import os
import time
import pandas as pd
import numpy as np
import re
import hashlib
from oletools.olevba import VBA_Parser, VBA_Scanner
from scipy import stats
from sklearn.externals import joblib
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.feature_extraction.text import TfidfTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn import preprocessing, neighbors
from sklearn.model_selection import cross_val_score
import json

class MaliciousMacroBot:
    def __init__(self, benign_path="./model/benign_samples", malicious_path="./model/malicious_samples", model_path="./model"):
        '''
        benign_path is the directory path (relative or absolute) to benign documents for the machine learning model to learn from.
        malicious_path is the directory path (relative or absolute) to malicious documents for the machine learning model to learn from.  It sub-folders can be created under the malicious_path to contain specific families like ./malicious_path/LOCKY or ./malicious_path/HANCITOR and the learning algorithm will us the folders in the family prediction.
        model_path is the directory where model files and helpful data will be saved for the algorithm to function.
        '''
        self.cls = None
        self.knn_alldata_clf = None
        self.modeldata = None
        self.features = {}
        self.set_model_paths(os.path.dirname(benign_path),
                             os.path.dirname(malicious_path), 
                             os.path.dirname(model_path))


    def getFileHash(self, pathtofile):
        '''
        Given absolute or relative path to file, returns MD5 hash of the file
        '''
        if os.path.isfile(pathtofile):
            with open(pathtofile, 'rb') as file_to_hash:
                filedata = file_to_hash.read()
                md5 = hashlib.md5(filedata).hexdigest()
                #sha1 = hashlib.sha1(filedata).hexdigest()
                #sha256 = hashlib.sha256(filedata).hexdigest()
                return md5
        return None


    def fillMissingHashes(self, row):
        '''
        Checks if there is a null or NaN value for the 'md5' column.  If so, computes it, if not,
        returns original value.  Used to fill in missing md5's in a dataframe.
        '''
        if pd.isnull(row['md5']):
            return self.getFileHash(row['filepath'])
        else:
            return row['md5']


    def getFileMetaData(self, filepath, filename=None, getHash=False):
        '''
        helper function to get meta information about a file to include it's path, date modified, size
        '''
        if filename is None:
            filename = os.path.split(filepath)[1]
 
        filemodified = time.ctime(os.path.getmtime(filepath))
        filesize = os.path.getsize(filepath)
        md5 = np.nan
        if getHash:
            md5 = self.getFileHash(filepath)
        return (filename, filepath, filesize, filemodified, md5)
 

    def getSamplesFromDisk(self, path=None, getHash=False):
        '''
        Given a path to a file or folder of files, returns a dataframe with the 
        recursive listing of filename, filepath, filesize, modified date, and md5 hash.
        '''
        if not os.path.exists(path):
            raise IOError("ERROR: File or path does not exist: {}".format(path,))

        if os.path.isfile(path):
            meta = self.getFileMetaData(path, getHash=getHash)
            return pd.DataFrame({'filename':(meta[0],),
                                 'filepath':(meta[1],),
                                 'filesize':(meta[2],),
                                 'filemodified':(meta[3],),
                                 'md5':(meta[4],)})

        try:
            matches = []
            for root, dirnames, filenames in os.walk(path):
                for filename in filenames:
                    filepath = os.path.join(root, filename)
                    meta = self.getFileMetaData(filepath, filename, getHash=getHash)
                    matches.append(meta)
            if len(matches) > 0:
                filenames,paths,sizes,dates,md5s = zip(*matches)
                return pd.DataFrame({'filename':filenames, 'filepath':paths, 'filesize':sizes, \
                                 'filemodified':dates, 'md5':md5s})
            return pd.DataFrame()
        except Exception, e:
            raise IOError("ERROR with file or path {}: {}".format(path,str(e)))

    def getFamilyName(self, filepath):
        '''
        Returns the family name of samples loaded from disk if provided and 'Unknown' otherwise
        '''
        dirname = os.path.dirname(filepath)
        dirname = dirname.replace(self.benign_path, "")
        dirname = dirname.replace(self.malicious_path, "")
        dirname = dirname.strip()
        if len(dirname) <= 0:
            familyName = "Unknown"
        elif dirname[0] == "/" or dirname[0] == "\\":
            familyName = dirname[1:]
        else:
            familyName = dirname
           
        return familyName


    def newSamples(self, existing, possiblenew):
        '''
        Returns dataframe containing rows from possiblenew with MD5 hashes are not in existing.
        '''
        existing_items = existing['md5'].tolist()
        possiblenew_items = possiblenew['md5'].tolist()
        actualnew_items = [x for x in possiblenew_items if x not in existing_items] 
        if len(actualnew_items) > 0:
            return possiblenew[possiblenew['md5'].isin(actualnew_items)].copy()
        return None


    def getLanguageFeatures(self):
        '''
        Prerequisite: loadModelData has been called, populating self.modeldata
        This function will tokenize the extracted_vba and create vector and tf-idf counts
        '''
        self.loadModelVocab()

        # Get custom VBA features
        self.modeldata[['function_names',
                          'vba_avg_param_per_func', 
                          'vba_cnt_comments',
                          'vba_cnt_functions',
                          'vba_cnt_loc',
                          'vba_cnt_func_loc_ratio',
                          'vba_cnt_comment_loc_ratio',
                          'vba_entropy_chars',
                          'vba_entropy_words',
                          'vba_entropy_func_names',
                          'vba_mean_loc_per_func']] = \
                        self.modeldata['extracted_vba'].apply(self.getVBAFeatures)

        tempfeatures = self.modeldata.columns 
        self.features['vba_features'] = [x for x in tempfeatures if x.startswith('vba_')]

        # Count Vectorizer
        corpus = self.modeldata.ix[:,'extracted_vba']
        self.model_cntvect = CountVectorizer(vocabulary=self.features['vocab'], 
                             lowercase=False,
                             decode_error='ignore',
                             token_pattern=r"(?u)\b\w[\w\.]+\b")
        self.modeldata_cnts = self.model_cntvect.fit_transform(corpus)
        self.features['cnt_features'] = ['cnt_' + x for x in self.model_cntvect.get_feature_names()]
        self.features['features'] = self.model_cntvect.get_feature_names() 
        self.modeldata = self.modeldata.join(pd.DataFrame(self.modeldata_cnts.toarray(),
                                                columns=self.features['cnt_features']))

        # TF-IDF Transformer
        self.model_tfidf_trans = TfidfTransformer() 
        self.model_tfidf_cntvect = self.model_tfidf_trans.fit_transform(self.modeldata_cnts.toarray())
        self.features['tfidf_features'] = ['tfidf_' + x for x in self.model_cntvect.get_feature_names()]
        self.modeldata = self.modeldata.join(pd.DataFrame(self.model_tfidf_cntvect.toarray(),
                                                columns=self.features['tfidf_features']))

        # Train and Test Model
        predictive_features = self.features['tfidf_features'] + self.features['vba_features']
        self.features['predictive_features'] = predictive_features
        self.clf_X = self.modeldata[predictive_features].as_matrix()
        self.clf_y = np.array(self.modeldata['label'])

        return {'X': self.clf_X, 'y':self.clf_y}


    def clearModelFeatures(self):
        '''
        Removes all columns from modeldata with names starting with cnt_, tfidf_, or vba_
        These are the computed columns for the model
        '''
        if self.modeldata is not None:
            columns = self.modeldata.columns
            cntcolumns = [x for x in columns if x.startswith('cnt_')]
            vba_feature_columns = [x for x in columns if x.startswith('vba_')]
            tfidfcolumns = [x for x in columns if x.startswith('tfidf_')]
            self.modeldata.drop(self.modeldata[cntcolumns], axis=1, inplace=True)
            self.modeldata.drop(self.modeldata[vba_feature_columns], axis=1, inplace=True)
            self.modeldata.drop(self.modeldata[tfidfcolumns], axis=1, inplace=True)


    def buildModels(self):
        '''
        After getLanguageFeatures is called, this function builds the models based on 
        the classifier matrix and labels.
        '''
        self.cls = RandomForestClassifier()
        # build classifier
        self.cls.fit(self.clf_X, self.clf_y)

        # build nearest neighbor for getting most similar files 
        self.knn_alldata_clf = neighbors.KNeighborsClassifier()
        self.knn_alldata_clf.fit(self.clf_X, self.clf_y)

        return self.cls


    def loadModelVocab(self):
        '''
        Loads vocabulary used in the bag of words model
        '''
        with open(self.vba_vocab) as vocabfile:
            lines = vocabfile.readlines()
            lines = [x.strip() for x in lines]
        self.features['vocab'] = set(lines)
        return self.features['vocab']


    def loadModelData(self, exclude=None):
        '''
        loads previously saved data (if exists) and merges with new files found in
        malicious and benign doc paths.

        exclude is a string - if samples used in the model contain this string,
        they will be omitted from the model.  This is primarily used to hold malware
        families from consideration in the model to assess classification generalization
        to new unknown families.
        '''
        knowndocs = None
        newdoc_cnt = 0

        try:
            knowndocs = pd.read_pickle(self.modeldata_pickle)
        except Exception, e:
            print "No usable pre-existing saved model data found: {}".format(str(e))
            knowndocs = None

        maldocs = self.getSamplesFromDisk(self.malicious_path)
        if len(maldocs) > 0:
            maldocs['label'] = 'malicious'
    
        benigndocs = self.getSamplesFromDisk(self.benign_path)
        if len(benigndocs) > 0:
            benigndocs['label'] = 'benign'
  
        if len(benigndocs) == 0 and len(maldocs) == 0 and knowndocs is None:
            raise IOError("ERROR: Unable to load saved model data {} or process samples rooted in model path {}.  Unable to make predictions.".format(self.modeldata_pickle, self.model_path))

        possiblenew = pd.concat([maldocs, benigndocs], axis=0)

        if knowndocs is None:
            # No existing samples, so alldocs are newly found docs.
            possiblenew['md5'] = possiblenew['filepath'].apply(self.getFileHash)
            possiblenew[['extracted_vba', 'stream_path', 'filename_vba']] = possiblenew['filepath'].apply(self.getVBA)
            possiblenew['family'] = possiblenew['filepath'].apply(self.getFamilyName)
            alldocs = possiblenew
            newdoc_cnt = len(alldocs)
        else:
            temp = knowndocs.append(possiblenew)
            # Omit seemingly duplicate files with same filepath, filesize and modified date
            grouped_rows = temp.groupby(['filesize', 'filepath', 'filemodified'])
            omit = grouped_rows.filter(lambda x: len(x)>1)['filepath'].unique()
            temp = temp[~((temp['filepath'].isin(omit)) & temp['md5'].isnull())].reset_index(drop=True)
            # Compute hashes for those that are new.  Omit files with duplicate md5 hashes
            temp['md5'] = temp.apply(self.fillMissingHashes, axis=1)
            temp = temp.drop_duplicates(subset='md5', keep='first')
            temp.reset_index(drop=True)

            newdocs = temp[temp['extracted_vba'].isnull()]
            knowndocs = temp[~temp['extracted_vba'].isnull()]

            # get enrichment for truly new docs
            if len(newdocs) > 0:
                print "%d NEW DOCS FOUND!" % (len(newdocs),)
                print newdocs[['filename','filemodified','filesize', 'filepath']]
                newdocs[['extracted_vba', 'stream_path', 'filename_vba']] = newdocs['filepath'].apply(self.getVBA)
                newdoc_cnt = len(newdocs)
                newdocs['family'] = newdocs['filepath'].apply(self.getFamilyName)
                alldocs = pd.concat([knowndocs, newdocs], axis=0)
                alldocs = alldocs.reset_index(drop=True)

            else:
                print "No new model data found"
                alldocs = knowndocs

        # keep only what we'll be working with
        if exclude is not None:
            self.modeldata = alldocs.drop(alldocs[alldocs['filepath'].str.contains(exclude)].index)
        else:
            self.modeldata = alldocs

        return newdoc_cnt 


    def saveModels(self):
        '''
        Saves all necessary model state information for classification work to disk.
        returns True if it succeeded and False otherwise.
        '''
        success = True
        try:
            pd.to_pickle(self.features, self.features_pickle)
        except Exception, e:
            print "Error saving features to disk: {}".format(str(e))
            success = False
        try:
            joblib.dump(self.model_tfidf_trans, self.model_tfidf_trans_pickle)
        except Exception, e:
            print "Error saving tfidf to disk: {}".format(str(e))
            success = False
        try:
            joblib.dump(self.model_cntvect, self.model_cntvect_pickle)
        except Exception, e:
            print "Error saving countvector to disk: {}".format(str(e))
            success = False
        try:
            pd.to_pickle(self.modeldata, self.modeldata_pickle)
        except Exception, e:
            print "Error saving model data to disk: {}".format(str(e))
            success = False
        try:
            joblib.dump(self.knn_alldata_clf, self.model_knn_all_pickle)
        except Exception, e:
            print "Error saving nearest neighbors to disk: {}".format(str(e))
            success = False
        try:
            joblib.dump(self.cls, self.model_cls_pickle)
        except Exception, e:
            print "Error saving classifier to disk: {}".format(str(e))
            success = False
        return success


    def loadModels(self):
        '''
        Loads all necessary state information for classification to work from disk.
        returns False if it failed and True otherwise.
        '''
        self.features = {}
        self.mode_tfidf_trans = None
        self.model_cntvect = None
        self.modeldata = None
        self.cls = None
        self.knn_alldata_clf = None

        try:
            self.features = pd.read_pickle(self.features_pickle)
        except Exception, e:
            print "Warning could not load features from disk: {}".format(str(e))
        try:
            self.model_tfidf_trans = joblib.load(self.model_tfidf_trans_pickle)
        except:
            print "Warning could not load tfidf data from disk: {}".format(str(e))
        try:
            self.model_cntvect = joblib.load(self.model_cntvect_pickle)
        except:
            print "Warning could not load count vector from disk: {}".format(str(e))
        try:
            self.modeldata = pd.read_pickle(self.modeldata_pickle)
        except:
            print "Warning could not load modeldata from disk: {}".format(str(e))
        try:
            self.knn_alldata_clf = joblib.load(self.model_knn_all_pickle)
        except:
            print "Warning could not load nearest neighbor classifier from disk: {}".format(str(e))
        try:
            self.cls = joblib.load(self.model_cls_pickle)
        except:
            print "Warning could not load classifier data from disk: {}".format(str(e))

        if (self.features is None or len(self.features) == 0) or \
           (self.model_tfidf_trans is None) or \
           (self.model_cntvect is None) or (self.modeldata is None) or \
           (self.cls is None) or (self.knn_alldata_clf is None):
            return False
        return True


    def getVBA(self, myfile, source='filepath'):
        '''
        Given a file, parses out the stream paths, vba code, and vba filenames for each.
        source is either "filepath" to indicate we need to read from disk or "filecontents"
        meaning that the file contents are being passed as a parameter.

        Usage Example:
        df[['stream_path', 'extracted_vba','filename_vba']] = df['filepath'].apply(getVBA)
        '''
        if source == 'filepath':
            filedata = open(myfile, 'rb').read()
        else:
            filedata = myfile
        
        entry = {}
        try:
            vbaparser = VBA_Parser('mmbot', data=filedata)
            allcode = ''
            pathnames = None
            filenames = None
            
            if vbaparser.detect_vba_macros():
                for (filename, stream_path, filename_vba, extracted_vba) in vbaparser.extract_macros():
                    spacer = "' ====== StreamPath: {} FileName: {} ====== ".format(stream_path,filename_vba)
                    allcode = "{}\n{}\n{}\n".format(allcode, spacer, extracted_vba)
                    if pathnames is None:
                        pathnames = stream_path
                        filenames = filename_vba
                    else:
                        pathnames = "{};{}".format(pathnames, stream_path)
                        filenames = "{};{}".format(filenames, filename_vba)
            else:
                pathnames = 'No VBA Macros found'
                filenames = 'No VBA Macros found'
                allcode = 'No VBA Macros found'
            
        except Exception, e:
            pathnames = 'Error:' + str(e)
            filenames = 'Error:' + str(e)
            allcode = 'Error:' + str(e)        
    
        return pd.Series({'extracted_vba':allcode,'stream_path':pathnames,'filename_vba':filenames})


    def getEntropy(self, vbcodeSeries):
        '''
        Given a pandas series of values, returns the entropy of the set of values.
        '''
        probs = vbcodeSeries.value_counts() / len(vbcodeSeries)
        entropy = stats.entropy(probs)
        return entropy
       
 
    def getVBAFeatures(self, vb):
        '''
        Given VB code as a string input, returns various summary data about it.
 
        Example:
        df[['vba_entropy_chars', 'vba_entropy_words', 
            'vba_functions', 'vba_cnt_loc', 
            'vba_mean_loc_per_func', 'vba_cnt_comments', 
            'vba_cnt_functions']] = \
            df['extracted_vba'].apply(getVBAFeatures)
        '''
        allfunctions = []
        all_num_functions = []
        all_locs = []
        entropy_func_names = 0
        avg_param_per_func = 0.0
        functions_str = ''
        vba_cnt_func_loc_ratio = 0.0
        vba_cnt_comment_loc_ratio = 0.0

        if vb == 'No VBA Macros found' or vb[0:6] == 'Error:':
            functions = 'None'
            num_functions = 0
            loc = 0
            avg_loc_func = 0
            num_comments = 0
            entropy_chars = 0
            entropy_words = 0
        else:
            functions = {}
            num_comments = vb.count("'")
            lines = vb.splitlines()
            new_lines = []
            num_functions = 0
            entropy_chars = self.getEntropy(pd.Series(vb.split(' ')))
            entropy_words = self.getEntropy(pd.Series(list(vb)))
            reFunction = re.compile(r'.*\s?[Sub|Function]\s+([a-zA-Z0-9_]+)\((.*)\)')
            for line in lines:
                if len(line.strip()) > 0:
                    new_lines.append(line)
    
                function_name_matches = reFunction.findall(line)
                num_params = 0
                if len(function_name_matches) > 0:
                    num_functions = num_functions + 1
                    num_params = function_name_matches[0][1].count(',') + 1
                    if len(function_name_matches[0][1].strip()) <= 0:
                        num_params = 0
                    functions[function_name_matches[0][0]] = num_params
    
            loc = len(new_lines)
            if len(functions) > 0:
                function_name_str = ''.join(functions.keys())
                entropy_func_names = self.getEntropy(pd.Series(list(function_name_str)))
                functions_str = ', '.join(functions.keys())
                param_list = functions.values()
                avg_param_per_func = (1.0 * sum(param_list)) / len(param_list) 
            if loc > 0:
                vba_cnt_func_loc_ratio = (1.0*len(functions))/loc
                vba_cnt_comment_loc_ratio = (1.0*num_comments)/loc
            if num_functions <= 0:
                avg_loc_func = float(loc)
            else:
                avg_loc_func = float(loc) / num_functions
            
        return pd.Series({'function_names' : functions_str,
                          'vba_avg_param_per_func' : avg_param_per_func,
                          'vba_cnt_comments' : num_comments,
                          'vba_cnt_functions': num_functions,
                          'vba_cnt_loc':loc,
                          'vba_cnt_func_loc_ratio' : vba_cnt_func_loc_ratio,
                          'vba_cnt_comment_loc_ratio' : vba_cnt_comment_loc_ratio,
                          'vba_entropy_chars' : entropy_chars,
                          'vba_entropy_words' : entropy_words,
                          'vba_entropy_func_names': entropy_func_names,
                          'vba_mean_loc_per_func':avg_loc_func
                         })

                        
    def set_model_paths(self, benign_path, malicious_path, model_path):
        self.benign_path = benign_path
        self.malicious_path = malicious_path
        self.model_path = model_path

        self.modeldata_pickle = os.path.join(self.model_path, 'modeldata.pickle')
        self.features_pickle = os.path.join(self.model_path, 'features.pickle')
        self.vba_vocab = os.path.join(model_path, 'vba_vocab.txt')
        self.model_cls_pickle = os.path.join(model_path, 'model_classifier.pickle')
        self.model_knn_benign_pickle = os.path.join(model_path, 'model_knn_benign.pickle')
        self.model_knn_malicious_pickle = os.path.join(model_path, 'model_knn_malicious.pickle')
        self.model_knn_all_pickle = os.path.join(model_path, 'model_knn_all.pickle')
        self.model_tfidf_trans_pickle = os.path.join(model_path, 'model_tfidf_trans.pickle')
        self.model_cntvect_pickle = os.path.join(model_path, 'model_cntvect.pickle')


    def getTopVBAFeatures(self, sample, top=5):
        '''
        Sample is a dictionary result from a classification prediction
        top is the number of ranked features to return.
        Funtion returns a dictionary of the top VBA features ranking and counts that
        contributed to the prediction.
        '''
        relevantFeatures = []

        nonzero_tfidf_features = np.array(sample[self.features['tfidf_features']]).nonzero()
        sample_tfidf_features_row = np.array(sample[self.features['tfidf_features']])[0]
        sample_cnt_row = np.array(sample[self.features['cnt_features']])

        # Collect information for all features that helped with the prediction
        for i in nonzero_tfidf_features[1]:
            feature_name = (self.features['tfidf_features'][i])
            feature_value = sample_tfidf_features_row[i]
            if feature_name.startswith("tfidf_"):
                feature_cnt = sample[feature_name.replace("tfidf_", "cnt_")].iloc[0]
            else: 
                feature_cnt = feature_value
            feature_name = feature_name.replace("tfidf_","")
            relevantFeatures.append((feature_name, feature_value, feature_cnt))

        # Sort all features that aided in prediction by their relative importance
        result = sorted(relevantFeatures, key=lambda x: x[1], reverse=True)
       
        if top >= len(result):
            top = len(result) - 1
        flat_top_features = {}
        names = {'feat_'+str(x)+'_name':result[x][0] for x in range(1,(top+1))}
        importance = {'feat_'+str(x)+'_importance':result[x][1] for x in range(1,(top+1))}
        counts = {'feat_'+str(x)+'_cnt':result[x][2] for x in range(1,(top+1))}

        nested_top_features = []
        for x in range(1,(top+1)):
            nested_top_features.append({'name':result[x][0], 
                                        'importance':int(round(100*result[x][1])), 
                                        'cnt':result[x][2], 
                                       })

        flat_top_features.update(names)
        flat_top_features.update(importance)
        flat_top_features.update(counts)
 
        return (flat_top_features, nested_top_features)


    def classifyVBA(self, vba):
        '''
        Applies classification model for prediction and clustering related samples to 
        vba input provided as a pandas Series.

        Returns results as a pandas Series
        '''
        sample = pd.DataFrame(data=[vba], columns=['extracted_vba'])

        newsample_cnt = self.model_cntvect.transform(sample['extracted_vba']).toarray()
        newsample_tfidf = self.model_tfidf_trans.transform(newsample_cnt).toarray()
        newsample_df = pd.DataFrame()
        newsample_df = pd.DataFrame(self.getVBAFeatures(vba)).T

        predictive_features = self.features['tfidf_features'] + self.features['vba_features']

        # Join all features for this sample into one dataframe
        newsample_df_cnt = pd.DataFrame(newsample_cnt, columns=self.features['cnt_features'])
        newsample_df_tfidf = pd.DataFrame(newsample_tfidf, columns=self.features['tfidf_features'])
 
        newsample_df = newsample_df.join(newsample_df_cnt)
        newsample_df = newsample_df.join(newsample_df_tfidf)

        newsample = newsample_df[predictive_features].as_matrix()
         
        prediction = self.cls.predict(newsample)
        neighbors = self.knn_alldata_clf.kneighbors(newsample, n_neighbors=5)

        # Assemble results as a flat dictionary and nested dictionary
        vba_feature_results = self.getTopVBAFeatures(newsample_df, top=5)
        flat_result_dictionary = vba_feature_results[0]
        neighbor_results = self.formatNeighborResult(neighbors)
        flat_result_dictionary.update(neighbor_results[0])

        nested_dictionary = {'neighbors':neighbor_results[1],
                             'vba_lang_features':vba_feature_results[1]}

        for feature in self.features['vba_features']:
            flat_result_dictionary[feature] = newsample_df[feature].iloc[0]
            if isinstance(newsample_df[feature].iloc[0], (np.float64, float)):
                nested_dictionary[feature] = round(newsample_df[feature].iloc[0],2)
            else:
                nested_dictionary[feature] = newsample_df[feature].iloc[0]

        nested_dictionary['function_names'] = newsample_df['function_names'].iloc[0]
        nested_dictionary['prediction'] = prediction[0]

        flat_result_dictionary['function_names'] = newsample_df['function_names'].iloc[0]
        flat_result_dictionary['prediction'] = prediction[0]
        flat_result_dictionary['result_dictionary'] = nested_dictionary

        return pd.Series(flat_result_dictionary)


    def formatNeighborResult(self, neighbors, high_low_threshold=250):
        '''
        Takes in a result from nearest neighbor prediction and maps the selection back to the
        saved modeldata about the original malware training set
        '''
        flat_summary = {}
        nested_summary = []
        neighbors_close = []
        neighbors_far = []
        distances = []

        for i in range(len(neighbors[0][0])):
            cur_neighbor = 'neigh_'+str(i+1)+'_'

            index = neighbors[1][0][i]
            series = self.modeldata.iloc[index]

            flat_summary[cur_neighbor+'distance'] = neighbors[0][0][i]
            flat_summary[cur_neighbor+'order'] = str(i+1)
            flat_summary[cur_neighbor+'label'] = series['label']
            flat_summary[cur_neighbor+'md5'] = series['md5']
            flat_summary[cur_neighbor+'family'] = series['family']

            distances.append(neighbors[0][0][i])
            if(neighbors[0][0][i] > high_low_threshold):
                neighbors_far.append(series['family'])
            else:
                neighbors_close.append(series['family'])
            nested_summary.append({'distance':int(round(neighbors[0][0][i])),
                                   'order':str(i+1),
                                   'label':series['label'],
                                   'md5':series['md5'],
                                   'family':series['family']
                                  })
        if len(distances) > 0:
            avg_distances = round(sum(distances)/float(len(distances)),2)
            nested_summary.append({'neighbor_avg_distance':avg_distances})
        nested_summary.append({'neighbors_far':neighbors_far})
        nested_summary.append({'neighbors_close':neighbors_close})

        return (flat_summary, nested_summary)


    def mmb_init_model(self, modelRebuild=False, exclude=None):
        '''
        Initiates the machine learning models used order to begin making predictions.

        modelRebuild - boolean used to rebuild the model by looking for new samples
        on disk or just load the old model without checking for new samples.  If no
        saved models are found, it will attempt to rebuild from samples in the model directories.

        exclude is a string - if samples used in the model contain this string,
        they will be omitted from the model.  This is primarily used to hold malware
        families from consideration in the model to test the algorithm for classification generalization
        to unknown families and techniques.

        returns True if successful and False otherwise.
        '''
        modelsLoaded = self.loadModels()

        if modelRebuild or not modelsLoaded:
            newdoc_cnt = self.loadModelData(exclude)
            if newdoc_cnt > 0:
                self.clearModelFeatures()
                self.getLanguageFeatures()
                self.buildModels()
                modelsLoaded = self.saveModels()
            if (self.modeldata is None) or (len(self.modeldata) == 0):
                print '''No model data found, supervised machine learning requires 
                         labeled samples.  Check that samples exist in the benign_samples and
                         malicious_samples directories and that existing model files with .pickle
                         extensions exist in the existsmodels'''
                modelsLoaded = False
        return modelsLoaded
                   
        
    def mmb_evaluate_model(self):
        '''
        Returns scores from cross validation evaluation on the malicious / benign classifier
        '''
        predictive_features = self.features['predictive_features']
        self.clf_X = self.modeldata[predictive_features].as_matrix()
        self.clf_y = np.array(self.modeldata['label'])

        eval_cls = RandomForestClassifier()
        accuracy_scores = cross_val_score(eval_cls, self.clf_X, self.clf_y, cv=5 )
        f1_scores = cross_val_score(eval_cls, self.clf_X, self.clf_y, cv=5, scoring='f1_macro')

        return {'accuracy_scores':accuracy_scores, 'f1_scores':f1_scores}


    def mmb_predict(self, sample_input, datatype='filecontents'):
        '''
        Given a suspicious office file input, make a prediction on whether it is benign or malicious
        and provide nearest neighbor information as well as some key statistics.

        sample_input is the input to be used in the prediction.  It may be: 
          - a python string of already extracted VBA
          - a file read into a buffer (e.g. with the open().read() with the 'rb' flag), which is of type str
          - a directory path to a specific file or directory containing many files to be classified
          - a pandas DataFrame containing any of the three scenarios listed above and column names of either 'filepath', 'filecontents', or 'extracted_vba'
        datatype is a string indicating the type of information in the sample_input field 
        and must be one of the following three values 'vba', 'filecontents', or 'filepath'.
 
        Returns a 'dataframe' with the prediction results
        '''
        if not isinstance(sample_input, (str, pd.DataFrame)):
            raise TypeError("sample_input must be either a string or pandas DataFrame")
        if len(sample_input) <= 0:
            return pd.DataFrame()
                
        sample = None
        if datatype == 'filepath':
            if isinstance(sample_input, str):
                sample = self.getSamplesFromDisk(sample_input, getHash=True)
            if isinstance(sample_input, pd.DataFrame):
                if 'filepath' not in sample_input.columns:
                    raise ValueError("DataFrame must contain a column named 'filepath'") 

                sample = pd.DataFrame()
                allfiles = []
                for i in range(len(sample_input)):
                    morefiles = self.getSamplesFromDisk(sample_input.iloc[i]['filepath'], getHash=True)
                    allfiles.append(morefiles)
                sample = sample.append(allfiles)
            sample = pd.concat([sample, sample.filepath.apply(self.getVBA)], axis=1)
        if datatype == 'filecontents':
            if isinstance(sample_input, str):
                sample_vba = self.getVBA(sample_input, source=datatype)
                sample = pd.DataFrame([sample_vba])
            if isinstance(sample_input, pd.DataFrame):
                if 'filecontents' not in sample_input.columns:
                    raise ValueError("DataFrame must contain a column named 'filecontents'") 

                sample = pd.concat([sample_input, sample_input.filecontents.apply(self.getVBA, args=(datatype,))], axis=1)
        if datatype == 'vba':
            if isinstance(sample_input, str):
                sample = pd.DataFrame(data=[vba], columns=['extracted_vba'])
            if isinstance(sample_input, pd.DataFrame):
                if 'extracted_vba' not in sample_input.columns:
                    raise ValueError("DataFrame must contain a column named 'extracted_vba'") 
                sample = sample_input
        if sample is not None and len(sample) > 0:
            complete_result = pd.concat([sample, sample.extracted_vba.apply(self.classifyVBA)], axis=1)

            return complete_result 
        else:
            raise ValueError("Unexpected error occurred.") 

    def mmb_prediction_to_json(self, prediction):
        '''
        Given a prediction DataFrame obtained from calling mmb_predict(), return the
        json representation of the prediction results. 
        '''
        array = []
        if not isinstance(prediction, pd.DataFrame):
            raise ValueError("prediction parameter must be a DataFrame with a column named 'result_dictionary'") 

        if 'result_dictionary' not in prediction.columns:
            raise ValueError("DataFrame must contain a column named 'extracted_vba'") 

        for i in range(len(prediction)):
            array.append(prediction.iloc[0]['result_dictionary'])
        return json.dumps(array)

