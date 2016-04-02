import re
from socket import inet_pton, error, AF_INET, AF_INET6

# http://stackoverflow.com/questions/1418423/the-hostname-regex
NAME_PATTERN = re.compile('^(?=.{1,255}$)[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?(?:\.[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?)*\.?$')

#-------------------------------------------------------------------------------
# Comment parsing

def commented(line):
    if '#' in line:
        idx = line.index('#')
        return line[idx+1:]
    return ''

def uncommented(line):
    if '#' in line:
        idx = line.index('#')
        return line[:idx]
    return line

#-------------------------------------------------------------------------------
# Address & name validation

def is_address(s):
    for spec in [AF_INET, AF_INET6]:
        try:
            inet_pton(spec, s)
            return True
        except error:
            pass

    return False

def is_name(s):
    return bool(re.match(NAME_PATTERN, s))

#-------------------------------------------------------------------------------
# Line parsing

def parse_line(line):
    unc = uncommented(line).lstrip()
    com = commented(line).rstrip()

    if not com and not unc:
        return '', [], [], False

    if com and not unc:
        parts = com.split()
        if not is_address(parts[0]):
            return com, [], [], True

        addr, names, comment, _ = parse_line(com)
        return addr, names, comment, True

    parts = unc.split()
    if len(parts) < 2:
        raise ValueError("Line must contain one IP address and at least one "
                         "host name: {}".format(line))
    
    address = parts[0]
    names = parts[1:]
    
    return address, names, com, False

#-------------------------------------------------------------------------------
# Line representations


class Line(object):
    def __init__(self, address, names, comment='', is_comment=False):
        self.address = address
        self.names = list(names)
        self.comment = comment
        self.is_comment = is_comment

        self.validate()

    @classmethod
    def from_line(cls, line):
        address, names, comment, is_comment = parse_line(line)

        if not address and not is_comment:
            return Empty()

        if address and not names and is_comment:
            return Comment(address)

        return cls(address, names, comment, is_comment)

    def to_string(self):
        comment = ' #{}'.format(self.comment) if self.comment else ''
        return '{}{}\t{}{}'.format('# ' if self.is_comment else '',
                                   self.address,
                                   ' '.join(self.names),
                                   comment)

    def validate(self):
        if not is_address(self.address):
            raise ValueError("Attribute 'address' must be valid IP address")
        
        if not len(self.names) >= 1:
            raise ValueError("Attribute 'names' must have at least 1 member")

        for name in self.names:
            if not is_name(name):
                raise ValueError("Invalid hostname: {}".format(name))


class Empty(object):
    def to_string(self):
        return ''

    def validate(self):
        pass


class Comment(object):
    def __init__(self, text):
        self.text = text

    def to_string(self):
        return '#{}'.format(self.text)

    def validate(self):
        pass


#-------------------------------------------------------------------------------
# Hosts file representation


class HostsFile(object):
    def __init__(self, lines):
        self.lines = lines
        self.validate()

    @classmethod
    def from_path(cls, path):
        with open(path, 'rt') as f:
            txt = f.read()

        lines = txt.split('\n')
        objs = [Line.from_line(line) for line in lines]
        return cls(objs)

    def validate(self):
        for line in self.lines:
            if not isinstance(line, (Line, Empty, Comment)):
                raise TypeError("Attribute 'lines' is not list of Line objects")
            line.validate()


#-------------------------------------------------------------------------------
