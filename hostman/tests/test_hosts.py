from nose.tools import assert_raises
from hostman.hosts import commented, uncommented
from hostman.hosts import is_address, is_name
from hostman.hosts import parse_line, Line, Empty, Comment, HostsFile

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
    assert parse_line('') == ('', [], [], False)
    assert parse_line('  \t \t ') == ('', [], [], False)

    assert parse_line('# This is a comment') == (' This is a comment', [],
                                                 [], True)

    assert parse_line('8.8.8.8 dns1 dns2') == ('8.8.8.8', ['dns1', 'dns2'], 
                                               '', False)
    assert parse_line('8.8.8.8 dns1 #dns2') == ('8.8.8.8', ['dns1'], 'dns2',
                                                False)
    assert parse_line('8.8.8.8 dns#1 dns2') == ('8.8.8.8', ['dns'], '1 dns2',
                                                False)
    assert_raises(ValueError, parse_line, '8.8.8.8 #dns1 dns2')
    assert parse_line('#8.8.8.8 dns1 dns2') == ('8.8.8.8', ['dns1', 'dns2'], 
                                                '', True)
    assert parse_line('#8.8.8.8 dns1 # dns2') == ('8.8.8.8', ['dns1',], 
                                                  ' dns2', True)

#-------------------------------------------------------------------------------
# Line representations

def test_line_representations():
    e = Line.from_line('  \t ')
    assert isinstance(e, Empty)
    assert e.to_string() == ''
    e.validate()

    c = Line.from_line(' # abc def ')
    assert isinstance(c, Comment)
    assert c.text == ' abc def'
    assert c.to_string() == '# abc def'
    c.validate()

    l = Line.from_line('8.8.8.8 dns1 dns2')
    assert isinstance(l, Line)
    assert l.address == '8.8.8.8'
    assert l.names == ['dns1', 'dns2']
    assert l.comment == Comment()
    assert l.is_comment is False
    assert l.to_string() == '8.8.8.8\tdns1 dns2'

    l = Line.from_line('8.8.8.8 dns#1 dns2')
    assert isinstance(l, Line)
    assert l.address == '8.8.8.8'
    assert l.names == ['dns']
    assert l.comment.text == '1 dns2'
    assert l.comment.names == ['1', 'dns2']
    assert l.is_comment is False
    assert l.to_string() == '8.8.8.8\tdns #1 dns2'

    assert_raises(ValueError, Line.from_line, '8.8.8.8 #dns1 dns2')

    l = Line.from_line('#8.8.8.8 dns1 dns2')
    assert isinstance(l, Line)
    assert l.address == '8.8.8.8'
    assert l.names == ['dns1', 'dns2']
    assert l.comment.text == ''
    assert l.is_comment is True
    assert l.to_string() == '# 8.8.8.8\tdns1 dns2'

    l = Line.from_line('# 8.8.8.8 dns1 # dns2')
    assert isinstance(l, Line)
    assert l.address == '8.8.8.8'
    assert l.names == ['dns1']
    assert l.comment.text == ' dns2'
    assert l.is_comment is True
    assert l.to_string() == '# 8.8.8.8\tdns1 # dns2'

    assert_raises(ValueError, Line.from_line, 'abc foo bar')
    assert_raises(ValueError, Line.from_line, '8.8.8.8 dns?')
    assert_raises(ValueError, Line.from_line, '8.8.8.8')

    l.names = []
    l.validate()
    l.is_comment = False
    assert_raises(ValueError, l.validate)

    assert Empty().to_string() == ''

    c = Comment('abc def')
    assert c.to_string() == '#abc def'
    c.add_name('ghi')
    assert c.to_string() == '#abc def ghi'
    c.remove_name('def')
    assert c.to_string() == '#abc ghi'

    l = Line.from_line('8.8.8.8 abc def #foo bar')
    assert not l.is_host_commented('abc')
    assert not l.is_host_commented('def')
    assert not l.is_host_commented('ghi')
    assert l.is_host_commented('foo')
    assert l.is_host_commented('bar')

    assert l.to_string() == '8.8.8.8\tabc def #foo bar'
    l.uncomment_host('bar')
    assert l.to_string() == '8.8.8.8\tabc def bar #foo'
    l.uncomment_host('foo')
    assert l.to_string() == '8.8.8.8\tabc def bar foo'
    l.comment_host('abc')
    assert l.to_string() == '8.8.8.8\tdef bar foo #abc'
    l.remove_host('def')
    assert l.to_string() == '8.8.8.8\tbar foo #abc'
    l.remove_host('bar')
    assert l.to_string() == '8.8.8.8\tfoo #abc'
    l.comment_host('foo')
    assert l.to_string() == '# 8.8.8.8\t #abc foo'
    l.add_host('def')
    assert l.to_string() == '8.8.8.8\tdef #abc foo'

#-------------------------------------------------------------------------------
# Hosts file representation

def test_hostsfile():
    pass

#-------------------------------------------------------------------------------
