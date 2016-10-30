import pytest
from peekapp.main import main

def setup_module(module):
    print 'setup_module      module:{}'.format(module.__name__)

def teardown_module(module):
    print 'teardown_module   module:{}'.format(module.__name__)

def setup_function(function):
    print 'setup_function    function{}'.format(function.__name__)

def teardown_function(function):
    print 'teardown_function function:{}'.format(function.__name__)

@pytest.fixture
def blacklist():
    pass

@pytest.fixture
def logfile():
    pass
