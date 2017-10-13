from mmbot import MaliciousMacroBot
import pytest
import os
import shutil
import pandas as pd
import logging

testdir = './samples/'
benign_path = os.path.join(testdir, 'benign')
malicious_path = os.path.join(testdir, 'malicious')
model_path = os.path.join(testdir, 'model')
origsample_path = os.path.join(testdir, 'benign.xlsm')
empty_path = os.path.join(testdir, 'empty')

# four benign samples for testing purposes
sample = 'benign.xlsm'
sample1 = 'benign_1.xlsm'
sample2 = 'benign_2.xlsm'
sample3 = 'benign_3.xlsm'
vocab = 'vocab.txt'


def resetTest():
    """
    Resets test filesystem structure back to initial state
    """
    # remove artifacts from past tests, if they exist
    shutil.rmtree(benign_path, ignore_errors=True)
    shutil.rmtree(malicious_path, ignore_errors=True)
    shutil.rmtree(model_path, ignore_errors=True)
    shutil.rmtree(empty_path, ignore_errors=True)

    # make test directories
    os.mkdir(benign_path)  # benign training set
    os.mkdir(malicious_path)  # malicious training set
    os.mkdir(model_path)  # where model data is kept
    os.mkdir(empty_path)  # empty directory

    # setup malicious file for training set
    shutil.copy(os.path.join(testdir, sample1), os.path.join(malicious_path, sample1))     
    shutil.copy(os.path.join(testdir, sample2), os.path.join(benign_path, sample2))     
    shutil.copy(os.path.join(testdir, sample3), os.path.join(benign_path, sample3))     
    shutil.copy(os.path.join(testdir, vocab), os.path.join(model_path, vocab))     


def test_init():
    """
    Simple test to ensure initialization works properly
    """
    mmb = MaliciousMacroBot()
    assert 1 == 1


def test_init_none_paths():
    """
    Should raise an exception because all paths cannot be None
    """
    with pytest.raises(IOError) as ioe:
        mmb = MaliciousMacroBot(benign_path=None, malicious_path=None, model_path=None)
    assert 'ERROR: Supplied' in str(ioe.value)


def test_init_non_existent_paths():
    """
    Test should raise an exception because benign_path and malicious_path must exist if provided.
    """
    with pytest.raises(IOError) as ioe:
        mmb = MaliciousMacroBot(benign_path='madeuppath', malicious_path='madeuppath', model_path='madeuppath')
    assert 'ERROR: Supplied' in str(ioe.value)


def test_init_existent_but_empty_paths():
    """
    Test should not raise an exception until we try to load the samples and realize no samples exist
    """
    resetTest()
    try:
        mmb = MaliciousMacroBot(empty_path, empty_path, empty_path)
    except Exception:
        pytest.fail("Unexpected exception")


def test_init_files_in_directories():
    """
    Test ensures the mmb_init function can build a model based on the samples provided.
    """
    resetTest()
    mmb = MaliciousMacroBot(benign_path, 
                            malicious_path, 
                            model_path, retain_sample_contents=False)
    result = mmb.mmb_init_model(modelRebuild=True)
    os.remove(os.path.join(model_path, 'modeldata.pickle'))
    assert result


def test_init_files_in_directories_retain_contents():
    """
    Test ensures the mmb_init function can rebuild a model leveraging saved results
    without reprocessing all samples every time
    """
    # Create model with a few samples
    resetTest()
    mmb = MaliciousMacroBot(benign_path, 
                            malicious_path, 
                            model_path, retain_sample_contents=True)
    result = mmb.mmb_init_model(modelRebuild=True)

    shutil.copy(origsample_path, os.path.join(malicious_path, sample))

    # Add a file and rebuild
    mmb = MaliciousMacroBot(benign_path, 
                            malicious_path, 
                            model_path, retain_sample_contents=True)
    result = mmb.mmb_init_model(modelRebuild=True)
    assert result


def test_mmb_predict_sample_on_disk():
    """
    Test ensures the mmb_predict function can make a prediction from a single sample on disk.
    """
    resetTest()
    mmb = MaliciousMacroBot(benign_path,
                            malicious_path,
                            model_path, retain_sample_contents=False)
    result = mmb.mmb_init_model(modelRebuild=True)
    predresult = mmb.mmb_predict(origsample_path, datatype='filepath')
    predicted_label = predresult.iloc[0]['prediction'] 
    logging.info('predicted label: {}'.format(predicted_label))
    logging.info(mmb.mmb_prediction_to_json(predresult))
    logging.info('predicted label: {}'.format(predicted_label))

    assert(predicted_label == 'benign' or predicted_label == 'malicious')


def test_mmb_predict_sample_from_extracted_vba_df():
    """
    Test ensures the mmb_predict function can make a prediction from a single vba_sample.
    """
    resetTest()
    mmb = MaliciousMacroBot(benign_path,
                            malicious_path,
                            model_path, retain_sample_contents=False)
    result = mmb.mmb_init_model(modelRebuild=True)
    samplevba = 'MsgBox "this is vba"'
    predresult = mmb.mmb_predict(samplevba, datatype='vba')

    predicted_label = predresult.iloc[0]['prediction'] 
    logging.info('predicted label: {}'.format(predicted_label))

    assert(predicted_label == 'benign' or predicted_label == 'malicious')


def test_mmb_predict_sample_from_extracted_vba():
    """
    Test ensures the mmb_predict function can make a prediction from a single vba_sample.
    """
    resetTest()
    mmb = MaliciousMacroBot(benign_path,
                            malicious_path,
                            model_path, retain_sample_contents=False)
    result = mmb.mmb_init_model(modelRebuild=True)
    samplevba = ['MsgBox "this is vba"', 'If vba!="malicious"']
    sampledf = pd.DataFrame(samplevba, columns=['extracted_vba'])
    predresult = mmb.mmb_predict(sampledf, datatype='vba')

    predicted_label = predresult.iloc[0]['prediction'] 
    logging.info('predicted label: {}'.format(predicted_label))

    assert(predicted_label == 'benign' or predicted_label == 'malicious')


