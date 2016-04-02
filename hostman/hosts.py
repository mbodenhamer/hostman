import re
from collections import defaultdict
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
        self._update()
        self.validate()

    def _update(self):
        self.hosts = {}
        self.chosts = {}
        self.addrs = defaultdict(set)
        self.caddrs = defaultdict(set)

        for line in filter(lambda: not line.is_comment, self.lines):
            self.addrs[line.address].add(line)
            for host in line.names:
                self.hosts[host] = line

        for line in filter(lambda: line.is_comment, self.lines):
            self.caddrs[line.address].add(line)
            for host in line.names:
                self.chosts[host] = line

    @classmethod
    def from_path(cls, path):
        with open(path, 'rt') as f:
            return cls.from_text(f.read())

    @classmethod
    def from_text(cls, text):
        lines = text.split('\n')
        return cls([Line.from_line(line) for line in lines])

    def to_path(self, path):
        with open(path, 'wt') as f:
            f.write(self.to_text())

    def to_text(self):
        lines = [line.to_string() for line in self.lines]
        return '\n'.join(lines)

    def query_host(self, name):
        res = self.hosts.get(name, None)
        if res is not None:
            res = res.address
        return res

    def query_address(self, address):
        res = self.addrs[address]
        if res:
            ret = []
            for line in res:
                ret += line.names
            return ret
        return res

    def comment_host(self, name):
        pass

    def comment_address(self, address):
        for line in self.addrs[address]:
            line.is_comment = True
        self._update()

    def uncomment_host(self, name):
        pass

    def uncomment_address(self, address):
        for line in self.caddrs[address]:
            line.is_comment = False
        self._update()

    def update_address(self, old_address, new_address):
        pass

    def set_host(self, name, address):
        pass

    def remove_host(self, name, address):
        pass

    def remove_address(self, address, comments=False):
        for line in self.addrs[address]:
            self.lines.remove(line)
        if comments:
            for line in self.caddrs[address]:
                self.lines.remove(line)

    def update_host(self, name, address):
        pass

    def update(self, other, comments=False):
        pass

    def validate(self):
        for line in self.lines:
            if not isinstance(line, (Line, Empty, Comment)):
                raise TypeError("Attribute 'lines' is not list of Line objects")
            line.validate()

        # TODO: add warning for repeated hosts

#-------------------------------------------------------------------------------
