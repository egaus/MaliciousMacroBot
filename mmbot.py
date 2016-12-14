#! /usr/bin/env python
from oletools.olevba import VBA_Parser, VBA_Scanner
from os import listdir
from os.path import isfile, join
import os
import pandas as pd
import numpy as np
import re
import requests
import getpass
import configparser
import argparse
import sys
import hashlib
import time
import socket
from sklearn.externals import joblib
from pprint import pprint
from sklearn import preprocessing, cross_validation, neighbors
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.decomposition import TruncatedSVD
from sklearn.metrics import classification_report 
from sklearn.metrics import f1_score
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.feature_extraction.text import TfidfTransformer
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier



class MaliciousMacroBot:
    def __init__(self, configpath=None):
        '''
        configpath is the path to your config file e.g. /home/.../mmb.cfg
        '''
        self.cls = None
        self.knn_alldata_clf = None
        self.modeldata = None
        self.features = {}

        self.parseConfig(configpath)
        self.loadSavedData(self.configDir)


    def loadSavedData(self, path):
        '''
        Given a path to the config directory, attempt to load all models and dataset.
        '''
        # TODO: These pickled models are being rebuilt everytime, not being saved / loaded
        try:
            self.modeldata = pd.read_pickle(self.modeldata_pickle)
        except:
            self.modeldata = None
        try:
            self.model_knn_benign = joblib.load(self.model_knn_benign_pickle)
        except:
            self.model_knn_benign = None
        try:
            self.model_knn_malicious = joblib.load(self.model_knn_malicious_pickle)
        except:
            self.model_knn_malicious = None
        try:
             self.knn_alldata_clf = joblib.load(self.model_knn_all_pickle)
        except:
            self.model_knn_all = None
        try:
            self.cls = joblib.load(self.model_cls_pickle)
        except:
            self.cls = None
        try:
            self.features = pd.read_pickle(self.features_pickle)
        except:
            self.features = {} 
        try:
            self.model_tfidf_trans = joblib.load(self.model_tfidf_trans_pickle)
        except:
            self.model_tfidf_trans = None
        try:
            self.model_cntvect = joblib.load(self.model_cntvect_pickle)
        except:
            self.model_cntvect = None


    def getSecret(self, message=None):
        '''
        Used to prompt the user for a secret value and mask it's input
        '''
        if message is None:
            message = 'secret value:'
        return getpass.getpass(message)


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
        if os.path.isfile(path):
            meta = self.getFileMetaData(path, getHash=getHash)
            return pd.DataFrame({'filename':(meta[0],),
                                 'filepath':(meta[1],),
                                 'filesize':(meta[2],),
                                 'filemodifed':(meta[3],),
                                 'md5':(meta[4],)})

        try:
            matches = []
            for root, dirnames, filenames in os.walk(path):
                for filename in filenames:
                    filepath = os.path.join(root, filename)
                    meta = self.getFileMetaData(filepath, filename, getHash=getHash)
                    matches.append(meta)
            filenames,paths,sizes,dates,md5s = zip(*matches)
            return pd.DataFrame({'filename':filenames, 'filepath':paths, 'filesize':sizes, \
                                 'filemodified':dates, 'md5':md5s})
        except Exception, e:
            print "Error loading samples from path %s: %s" % (path, str(e))
            return None

 
    def parseConfig(self, path):
        '''
        Loads content of config file into class members, given path to the config file
        '''
        config = configparser.ConfigParser()
        config.read(path)
        self.vtAPIKey = config.get('MaliciousMacroBot', 'vt_api_key')
        self.benignDocsPath = config.get('MaliciousMacroBot', 'benign_docs')
        self.maliciousDocsPath = config.get('MaliciousMacroBot', 'malicious_docs')
        self.configDir = config.get('MaliciousMacroBot', 'config_directory')

        self.sampledata_pickle = os.path.join(self.configDir, 'samples.pickle')
        self.modeldata_pickle = os.path.join(self.configDir, 'model', 'modeldata.pickle')
        self.features_pickle = os.path.join(self.configDir, 'model', 'features.pickle')
        self.vba_vocab = os.path.join(self.configDir, 'model', 'vba_vocab.txt')
        self.model_cls_pickle = os.path.join(self.configDir, 'model', 'model_classifier.pickle')
        self.model_knn_benign_pickle = os.path.join(self.configDir, 'model', 'model_knn_benign.pickle')
        self.model_knn_malicious_pickle = os.path.join(self.configDir, 'model', 'model_knn_malicious.pickle')
        self.model_knn_all_pickle = os.path.join(self.configDir, 'model', 'model_knn_all.pickle')
        self.model_tfidf_trans_pickle = os.path.join(self.configDir, 'model', 'model_tfidf_trans.pickle')
        self.model_cntvect_pickle = os.path.join(self.configDir, 'model', 'model_cntvect.pickle')


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


    def isVTReachable(self):
        '''
        Check for connection to VirusTotal and return True or False
        '''
        try:
            # Try to resolve DNS to IP
            ip = socket.gethostbyname("www.virustotal.com")
            # Test if virustotal is reachable
            s = socket.create_connection((ip, 80), 2)
            print 'Able to reach VirusTotal'
            return True
        except:
            pass
        print 'No connection to virustotal available'
        return False


    def getEnrichment(self, df):
        '''
        This is where the features for vba_code is parsed out and enrichment from sources like
        VirusTotal is obtained.
        '''
        df[['stream_path', 'vba_code','vba_filename']] = df['filepath'].apply(self.getVBA)
        if self.isVTReachable():
            df[['TrendMicro','last_scan','positives','total']] = df['filename'].apply(self.vtGetLabels) 
            df.positives.fillna(0,inplace=True)
            df.total.fillna(0,inplace=True)
            df.TrendMicro.fillna('none',inplace=True)
            df = df.reset_index(drop=True)
        else:
            print "cannot reach VT"
            df['positives'] = 0 
            df['total'] = 0
            df['TrendMicro'] = 'none'
            df['last_scan'] = 'none'
        return df


    def getLanguageFeatures(self):
        '''
        Prerequisite: loadModelData has been called, populating self.modeldata
        This function will tokenize the vba_code and create vector and tf-idf counts
        '''
        self.loadModelVocab()

        # Clear Model Data modeldata
        self.clearModelFeatures()

        # Count Vectorizer
        self.features['corpus'] = self.modeldata.ix[:,'vba_code']
        self.model_cntvect = CountVectorizer(vocabulary=self.features['vocab'], 
                             lowercase=False,
                             decode_error='ignore',
                             token_pattern=r"(?u)\b\w[\w\.]+\b")
        self.modeldata_cnts = self.model_cntvect.fit_transform(self.features['corpus'])
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
        self.clf_X = self.model_tfidf_cntvect.toarray()
        self.clf_y = np.array(self.modeldata['label'])

        pd.to_pickle(self.features, self.features_pickle)
        joblib.dump(self.model_tfidf_trans, self.model_tfidf_trans_pickle)
        joblib.dump(self.model_cntvect, self.model_cntvect_pickle)
        pd.to_pickle(self.modeldata, self.modeldata_pickle)

        return {'X': self.clf_X, 'y':self.clf_y}


    def buildModels(self, classifier='RandomForest'):
        # Swap out classifier
        if classifier == 'KNN':
            self.cls = neighbors.KNeighborsClassifier()
        else:
            self.cls = RandomForestClassifier()
        # build classifier
        self.cls.fit(self.clf_X, self.clf_y)

        # build nearest neighbor for getting most similar files 
        self.knn_alldata_clf = neighbors.KNeighborsClassifier()
        self.knn_alldata_clf.fit(self.clf_X, self.clf_y)

        joblib.dump(self.knn_alldata_clf, self.model_knn_all_pickle)
        joblib.dump(self.cls, self.model_cls_pickle)

        return self.cls


    def parseClassReportRow(self, label, row):
        rex_class_report = re.compile(r'(\s*[a-zA-Z0-9_\-\/ ]+)\s\s+(\d\.\d\d)\s+(\d\.\d\d)\s+(\d\.\d\d)\s+([\d]{1,10})$')
        m = rex_class_report.match(row)
        result = {}
        if m:
            # precision, recall, f1-score, sample_size
            result = {label+"_precision":float(m.group(2)),
                      label+"_recall":float(m.group(3)),
                      label+"_f1_score":float(m.group(4)),
                      label+"_sample_size":int(m.group(5))}
        return result


    def parseClassReport(self, report):
        rows = report.split('\n')
        benign = rows[2].split(';')[0]
        malicious = rows[3].split(';')[0]
        avg = rows[5].split(';')[0]
        result = {}
        result.update(self.parseClassReportRow('benign', benign))
        result.update(self.parseClassReportRow('malicious', malicious))
        result.update(self.parseClassReportRow('avg', avg))
        return result


    def evalModel(self, iterations=1, classifier='RandomForest', excludes=[None]):
        evaluation_data = {}
        for exclude in excludes:
            self.loadModelData(exclude=exclude)
            self.getLanguageFeatures()
            for iteration in range(iterations):
                X_train, X_test, y_train, y_test = cross_validation.train_test_split(self.clf_X,self.clf_y,test_size=0.2)
                if classifier == 'RandomForest':
                    cls = RandomForestClassifier()
                cls.fit(X_train, y_train)
                y_pred = cls.predict(X_test)
                classification_perf_report = classification_report(y_test, y_pred)
                classification_accuracy = "{:.3f}".format(np.mean(y_test == y_pred))
                label = exclude
                if exclude is None:
                    label = 'All Samples'
                index = label + '_rnd_' + str(iteration).zfill(3)
                evaluation_data[index] = self.parseClassReport(classification_perf_report)
                evaluation_data[index]['iteration'] = str(iteration).zfill(3)
                evaluation_data[index]['label'] = label
                evaluation_data[index]['accuracy'] = float(classification_accuracy)
        # Construct and format dataframe
        df = pd.DataFrame(evaluation_data)
        df = df.T.reset_index()
        label = df['label']
        iteration = df['iteration']
        df.drop(labels=['iteration', 'label', 'index'], axis=1, inplace = True)
        df.insert(0, 'iteration', iteration)
        df.insert(0, 'label', label)
        fixtype = [x for x in df.columns if (x not in ['label', 'iteration'])]
        for fixthis in fixtype:
            df[fixthis] = df[fixthis].astype(float)
        return df

    


    def classifyVBA(self, vba):
        newsample_cnt = self.model_cntvect.transform(vba).toarray()
        newsample_tfidf = self.model_tfidf_trans.transform(newsample_cnt).toarray()

        prediction = self.cls.predict(newsample_tfidf)
        neighbors = self.knn_alldata_clf.kneighbors(newsample_tfidf)

        return {'prediction': prediction,
                'neighbors':neighbors,
                'cnt':newsample_cnt[0],
                'tfidf':newsample_tfidf[0]}


    def clearModelFeatures(self):
        '''
        Removes all columns from modeldata with names starting with cnt_ or tfidf_ 
        '''
        if self.modeldata is not None:
            columns = self.modeldata.columns
            cntcolumns = [x for x in columns if x.startswith('cnt_')]
            tfidfcolumns = [x for x in columns if x.startswith('tfidf_')]
            self.modeldata.drop(self.modeldata[cntcolumns], axis=1, inplace=True)
            self.modeldata.drop(self.modeldata[tfidfcolumns], axis=1, inplace=True)


    def getFeatureWeights(self):
        '''
        Returns the TF-IDF weights for each feature
        '''
        return self.model_tfidf_trans.idf_


    def getCntVector(self, sample_vba):
        '''
        Takes in a list or list of lists and returns an array() object with word counts.
        '''
        return self.model_cntvect.transform(sample_vba).toarray()


    def getTFIDFVector(self, sample_vba):
        newsamplearray = self.model_cntvect.transform(['completely Shell new MsgBox Dim malicious sample']).toarray()
        return self.model_tfidf_trans.transform(newsamplearray).toarray()


    def getVocabFeatureLabels(self):
        '''
        Returns a list of feature names (vocab words) from our word vector feature extractor 
        '''
        return cntvect.get_feature_names()


    def getVocabFeatureLabelIndex(self, name):
        '''
        Given a label feature name, return the column index to the values.
        In this context, name would be 'Dim' and the return value would be something like 5.
        '''
        return cntvect.vocabulary_.get(name)



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
        Parameter: exclude is a string.  If samples used in the model contain this string,
        they will be omitted from the model.  This is primarily used to hold malware
        families from consideration in the model to assess classification generalization
        to new unknown families.
        '''
        knowndocs = None
        try:
            knowndocs = pd.read_pickle(self.modeldata_pickle)
        except:
            print "No pre-existing saved data found"

        maldocs = self.getSamplesFromDisk(self.maliciousDocsPath)
        if maldocs is not None:
            maldocs['label'] = 'malicious'

        benigndocs = self.getSamplesFromDisk(self.benignDocsPath)
        if benigndocs is not None:
            benigndocs['label'] = 'benign'

        possiblenew = pd.concat([maldocs, benigndocs], axis=0)

        if knowndocs is None:
            # No existing samples, so alldocs is the newly found docs.
            possiblenew['md5'] = possiblenew['filepath'].apply(self.getFileHash)
            alldocs = self.getEnrichment(possiblenew)
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

            newdocs = temp[temp['vba_code'].isnull()]
            knowndocs = temp[~temp['vba_code'].isnull()]

            # get enrichment for truly new docs
            if len(newdocs) > 0:
                print "%d NEW DOCS FOUND!" % (len(newdocs),)
                print newdocs
                newenricheddocs = self.getEnrichment(newdocs)
                alldocs = pd.concat([knowndocs, newenricheddocs], axis=0)
                alldocs = alldocs.reset_index(drop=True)
            else:
                print "No new model data found"
                alldocs = knowndocs

        # Write everything to disk to retain data
        pd.to_pickle(alldocs, self.modeldata_pickle)

        # keep only what we'll be working with in memory
        if exclude is not None:
            self.modeldata = alldocs.drop(alldocs[alldocs['filepath'].str.contains(exclude)].index)
        else:
            self.modeldata = alldocs

        return self.modeldata


    def loadSamples(self, path):
        '''
        loads previously saved data (if exists) and merges with new files found in
        malicious and benign doc paths.
        '''
        knowndocs = None
        try:
            knowndocs = pd.read_pickle(self.sampledata_pickle)
        except:
            print "No pre-existing saved samples found"

        possiblenew = self.getSamplesFromDisk(path)
        if possiblenew is None:
            print "No samples found"
            return None

        possiblenew['label'] = 'unknown'

        if knowndocs is None:
            alldocs = self.getEnrichment(possiblenew)
        else:
            newdocs = self.newSamples(knowndocs, possiblenew)
            if newdocs != None:
                print "%d NEW DOCS FOUND!" % (len(newdocs),)
                newenricheddocs = self.getEnrichment(newdocs)
                print newdocs
                alldocs = pd.concat([knowndocs, newenricheddocs], axis=0)
                alldocs = alldocs.reset_index(drop=True)
            else:
                alldocs = None

        #print "Saving sample data to disk here"
        #pd.to_pickle(alldocs, self.sampledata_pickle)

        return alldocs


    def getVBA(self, pathtofile):
        '''
        Given the path to a file, parses out the stream paths, vba code, and vba filenames for each.
        Usage Example:
        df[['stream_path', 'vba_code','vba_filename']] = df['filepath'].apply(getVBA)
        '''
        filedata = open(pathtofile, 'rb').read()
        
        entry = {}
        try:
            vbaparser = VBA_Parser(pathtofile, data=filedata)
            allcode = ''
            pathnames = None
            filenames = None
            
            if vbaparser.detect_vba_macros():
                for (filename, stream_path, vba_filename, vba_code) in vbaparser.extract_macros():
                    spacer = "' ====== StreamPath: {} FileName: {} ====== ".format(stream_path,vba_filename)
                    allcode = "{}\n{}\n{}\n".format(allcode, spacer, vba_code)
                    if pathnames is None:
                        pathnames = stream_path
                        filenames = vba_filename
                    else:
                        pathnames = "{};{}".format(pathnames, stream_path)
                        filenames = "{};{}".format(filenames, vba_filename)
            else:
                pathnames = 'No VBA Macros found'
                filenames = 'No VBA Macros found'
                allcode = 'No VBA Macros found'
            
        except Exception, e:
            pathnames = 'Error:' + str(e)
            filenames = 'Error:' + str(e)
            allcode = 'Error:' + str(e)        
    
        return pd.Series({'stream_path':pathnames,'vba_code':allcode,'vba_filename':filenames})


    def vtGetLabels(self, myhash):
        '''
        Given a hash and api key for VirusTotal, returns a few of the fields from the report
        Example:
        df[['TrendMicro','last_scan','positives','total']] = df['filename'].apply(vtGetLabels, args=(apikey,))
        '''
        try:
            result = self.vtGetFileReport(myhash, self.vtAPIKey)
            print ".",
        except Exception, e:
            print str(e)
            label='error'
            last_scan='error'
            positives=-1
            total=-1
        try:
            positives = result['positives']
        except:
            positives = 0
        try:
            total = result['total']
        except:
            total = 0
        try:
            label = result['scans']['TrendMicro']['result']
        except:
            label = 'none'
        try:
            label = result['scans']['TrendMicro']['result']
        except:
            label = 'none' 
        try:
            last_scan = result['scan_date']
        except:
            last_scan = 'none'
    
        return pd.Series({'label':label,'last_scan':last_scan,'positives':positives,'total':total})
    
    
    def getVBFeatures(vb):
        '''
        Given VB code as a string input, returns various summary data about it.
    
        Example:
        df[['functions','loc','mean_loc_per_function','num_functions']] = df['vba_code'].apply(getVBFeatures)
        '''
        allfunctions = []
        all_num_functions = []
        all_locs = []
    
        if vb == 'No VBA Macros found' or vb[0:6] == 'Error:':
            functions = 'None'
            num_functions = 0
            loc = 0
            avg_loc_func = 0
        else:
            functions = {}
            lines = vb.splitlines()
            new_lines = []
            num_functions = 0
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
            if num_functions <= 0:
                avg_loc_func = float(loc)
            else:
                avg_loc_func = float(loc) / num_functions
        return pd.Series({'functions': functions, 
                          'loc':loc, 
                          'mean_loc_per_function':avg_loc_func,
                          'num_functions': num_functions})

    def vtGetFileReport(self, malHash, key):
        '''
        Retrieves json summary report for a file hash from VirusTotal private API
        '''
        params = {'apikey': key, 'resource': malHash}
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
        json_response = response.json()
        return json_response


    def getSparseMatrixLabelsValuesRow(self, X, feature_names, row, origDataset=None, origDatasetColumns=None):
        '''
        returns a dictionary with the frequency counts for each non-zero label
        
        X is a scipy sparse matrix
        feature names array (e.g. vectorizer.get_feature_names())
        row is the row of the matrix you are interested in
        origDataset is original pandas dataset with additional info you want
        '''
        nonzero = X.getrow(row).nonzero()[1]
        rowdata = X.getrow(row).toarray()[0]
        result = {}
        relevantFeatures = []
        for i in nonzero:
            relevantFeatures.append((feature_names[i], rowdata[i]))
        if (origDataset is not None) and (origDatasetColumns is not None):
            result['relevantFeatures'] = sorted(relevantFeatures, key=lambda x: x[1], reverse=True)
            result.update(origDataset.iloc[row][origDatasetColumns].to_dict())
            result['index'] = row
            return result
        return result
    
    
    def getSparseMatrixLabelsValuesList(self, X, feature_names, mylist, origDataset=None, origDatasetColumns=None):
        results = []
        for row in mylist:
            results.append(self.getSparseMatrixLabelsValuesRow(X, feature_names, row, origDataset, origDatasetColumns))
        return results
    
    
    def getSparseMatrixLabelsValues(self, row, origDatasetColumns=None):
        '''
        returns a list of dictionaries with the frequency counts for each non-zero label
        
        X is a scipy sparse matrix
        feature names array (e.g. vectorizer.get_feature_names())
        row is the row of the matrix you are interested in
        origDataset is original pandas dataset with additional info you want
        '''
        feature_names = self.clf_vectorizer.get_feature_names()
        origDatasetColumns = ['filename', 'vba_filename', 'positives', 'TrendMicro', 'label']

        if row is int:
            return [self.getSparseMatrixLabelsValuesRow(self.clf_X, feature_names, row, self.modeldata, origDatasetColumns)]
        else:
            return self.getSparseMatrixLabelsValuesList(self.clf_X, feature_names, row, self.modeldata, origDatasetColumns)

    def formatSampleResult(self, sample):
        '''
        Sample is a dictionary result from a classification prediction
        '''
        nonzero_tfidf = sample['tfidf'].nonzero()
        tfidf_row = sample['tfidf']
        cnt_row = sample['cnt']

        relevantFeatures = []
        for i in nonzero_tfidf[0]:
            relevantFeatures.append((self.features['features'][i], tfidf_row[i], cnt_row[i]))

        result = sorted(relevantFeatures, key=lambda x: x[1], reverse=True)
        df = pd.DataFrame(result, columns=['VBA', 'Significance Weight', 'Count'])
        df.index.name = 'Rank'
        return df


    def formatNeighborResult(self, neighbors):
        summary = []
        vba_details = [] 
        for i in range(len(neighbors[0][0])):
            distance = neighbors[0][0][i]
            index = neighbors[1][0][i]
            series = self.modeldata.iloc[index]
            result = {'rank':i,
                      'filename':series['filename'],
                      'distance':distance,
                      'label':series['label'],
                      'md5':series['md5'],
                      'TrendMicro':series['TrendMicro'],
                      'positives':series['positives'],
                      'total':series['total'],
                     }
            summary.append(result)
            sample = {'tfidf':series[self.features['tfidf_features']].as_matrix(),
                      'cnt':series[self.features['cnt_features']].as_matrix(),
                     }
            vba_details.append(self.formatSampleResult(sample))
        return [summary, vba_details]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='MaliciousMacroBot is a malicious document analysis tool using machine learning techniques to gain insights about whether a suspect document is malicious, determine what makes the document unique among others, and assist building a signature to detect it in the future.')
    parser.add_argument('-c', '--config', help='Path to configuration file')
    parser.add_argument('-s', '--sample', help='Sample to analyze or directory of files')
    parser.add_argument('-u', '--update_model', help='Update model and print out model classification performance details.', action='store_true')
    parser.add_argument('-e', '--evaluate_model', help='Assess model performance using cross validation test.', action='store_true')

    args = parser.parse_args()

    configDir = './config'
    sampleDir = './samples'

    if args.config:
        configDir = args.config
    else:
        print "\nA configuration file is required.\n"
        parser.print_help()
        print "\n"
        sys.exit(0) 

    mmb = MaliciousMacroBot(args.config)
    if mmb.cls is None or mmb.knn_alldata_clf is None or args.update_model:
        print "Loading Model Data..."
        docs = mmb.loadModelData()
        mmb.getLanguageFeatures()
        print "Loading samples provided"
        mmb.buildModels()

    if args.evaluate_model:
        df = mmb.evalModel(iterations=10, classifier='RandomForest', excludes=[None])
        print df[['label', 'benign_recall', 'benign_precision', 'benign_f1_score', 'accuracy', 'benign_sample_size', 'malicious_sample_size']].groupby(['label']).mean()

    if args.sample:
        sample = mmb.loadSamples(args.sample)

        result = mmb.classifyVBA(sample['vba_code'])
        df = mmb.formatSampleResult(result)
        print 'SAMPLE: %s' % (sample.ix[0, 'filename'],)
        print 'Prediction:%s TrendMicro:%s VT:%s/%s md5:%s' % (result['prediction'][0], sample.ix[0,'TrendMicro'], sample.ix[0, 'positives'], sample.ix[0, 'total'], sample.ix[0, 'md5'])
        print df

        print '\nSIMILAR DOCUMENTS:'
        neighbors_formatted = mmb.formatNeighborResult(result['neighbors'])
        neighbors_summary = pd.DataFrame(neighbors_formatted[0], columns=['filename', 'distance', 'label', 'TrendMicro', 'positives', 'total'])
        print neighbors_summary
        pprint(neighbors_formatted[1])

