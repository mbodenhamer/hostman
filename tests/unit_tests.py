from nose.tools import assert_raises
from hostman.hosts import commented, uncommented
from hostman.hosts import is_address, is_name
from hostman.hosts import parse_line, Line, HostsFile

#-------------------------------------------------------------------------------
# Comment parsing

def test_commented():
    assert commented('#8.8.8.8 dns1') == '8.8.8.8 dns1'
    assert commented('8.8.8.8 dns#1 dns2') == '1 dns2'
    assert commented('8.8.8.8 dns1') == ''

def test_uncommented():
    assert uncommented('#8.8.8.8 dns1') == ''
    assert uncommented('8.8.8.8 dns#1 dns2') == '8.8.8.8 dns'
    assert uncommented('8.8.8.8 dns1') == '8.8.8.8 dns1'

#-------------------------------------------------------------------------------
# Address & name validation

def test_is_address():
    assert is_address('1.1.1.1')
    assert not is_address('1.')
    assert not is_address('256.1.1.1')
    assert is_address('fe00::0')
    assert not is_address('fe00')

def test_is_name():
    assert is_name('abc')
    assert not is_name('abc?')
    assert is_name('abc.com')
    assert is_name('abc.xyz.com')
    assert is_name('abc-xyz.com')
    assert not is_name('abc xyz.com')

#-------------------------------------------------------------------------------
# Line parsing

def test_parse_line():
    assert parse_line('8.8.8.8 dns1 dns2') == ('8.8.8.8', ['dns1', 'dns2'], [])
    assert parse_line('8.8.8.8 dns1 #dns2') == ('8.8.8.8', ['dns1'], ['dns2'])
    assert parse_line('8.8.8.8 dns#1 dns2') == ('8.8.8.8', ['dns'], ['dns2'])
    assert_raises(ValueError, parse_line, '8.8.8.8 #dns1 dns2')
    assert parse_line('#8.8.8.8 dns1 dns2') == ('8.8.8.8', [], ['dns1', 'dns2'])

#-------------------------------------------------------------------------------
# Line representation

def test_line():
    l = Line.from_line('8.8.8.8 dns1 dns2')
    assert l.address == '8.8.8.8'
    assert l.names == ['dns1', 'dns2']
    assert l.commented_names == []
    assert l.is_commented is False

    l = Line.from_line('8.8.8.8 dns#1 dns2')
    assert l.address == '8.8.8.8'
    assert l.names == ['dns']
    assert l.commented_names == ['dns2']
    assert l.is_commented is False

    assert_raises(ValueError, Line.from_line, '8.8.8.8 #dns1 dns2')

    l = Line.from_line('#8.8.8.8 dns1 dns2')
    assert l.address == '8.8.8.8'
    assert l.names == ['dns1', 'dns2']
    assert l.commented_names == []
    assert l.is_commented is True

    assert_raises(ValueError, Line.from_line, 'abc foo bar')
    assert_raises(ValueError, Line.from_line, '8.8.8.8 dns?')

    l.names = []
    assert_raises(ValueError, l.validate)

#-------------------------------------------------------------------------------
# Hosts file representation

def test_hostsfile():
    pass

#-------------------------------------------------------------------------------
