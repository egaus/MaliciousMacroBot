from mmbot import MaliciousMacroBot 
import pytest

def test_init():
    '''
    Simple test to ensure initialization works properly
    '''
    mmb = MaliciousMacroBot()
    assert 1==1

def test_init_none_paths():
    '''
    Should raise an exception because all paths cannot be None
    '''
    with pytest.raises(IOError) as ioe:
        mmb = MaliciousMacroBot(benign_path=None, malicious_path=None, model_path=None)
    assert 'ERROR: Supplied' in str(ioe.value)

def test_init_non_existent_paths():
    '''
    Test should raise an exception because benign_path and malicious_path must exist if provided.
    '''
    with pytest.raises(IOError) as ioe:
        mmb = MaliciousMacroBot(benign_path='madeuppath', \
                                            malicious_path='madeuppath', \
                                            model_path='madeuppath')
    assert 'ERROR: Supplied' in str(ioe.value)

def test_init_existent_but_empty_paths():
    '''
    Test should not raise an exception until we try to load the samples and realize no samples exist
    '''
    try:
        mmb = MaliciousMacroBot(benign_path='./tests/empty', malicious_path='./tests/empty', model_path='./tests/empty')
    except Exception:
        pytest.fail("Unexpected exception")


def test_init_files_in_directories():
    #mmb = MaliciousMacroBot(benign_path='./tests/samples/benign', malicious_path='./tests/samples/malicious', model_path='./tests/samples/')
    mmb = MaliciousMacroBot(benign_path='./samples/benign', malicious_path='./samples/malicious', model_path='./samples/')
    import pdb; pdb.set_trace() 
    result = mmb.mmb_init_model(modelRebuild=True)
    assert(result)
    
test_init_files_in_directories()

