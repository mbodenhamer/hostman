import re
from syn.five import STR
from syn.type import List
from syn.base import Base, Attr, init_hook
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
    '''Returns address, names, comment, is_comment (see Line class).
    '''

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


class Line(Base):
    _attrs = dict(address = Attr(STR, doc='The IP address'),
                  names = Attr(List(STR), doc='A list of hostnames'),
                  comment = Attr(STR, '', "Content of this line's comment"),
                  is_comment = Attr(bool, False, 'True if this line is '
                                    'completely a comment'))
    _opts = dict(init_validate = True,
                 coerce_args = True,
                 args = ('address', 'names', 'comment', 'is_comment'))
    
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
        super(Line, self).validate()

        if not is_address(self.address):
            raise ValueError("Attribute 'address' must be valid IP address")
        
        if not len(self.names) >= 1:
            raise ValueError("Attribute 'names' must have at least 1 member")

        for name in self.names:
            if not is_name(name):
                raise ValueError("Invalid hostname: {}".format(name))


class Empty(Base):
    def to_string(self):
        return ''


class Comment(Base):
    _attrs = dict(text = Attr(str, doc='Text of the comment'))
    _opts = dict(args = ('text',))

    def to_string(self):
        return '#{}'.format(self.text)


#-------------------------------------------------------------------------------
# Hosts file representation


class HostsFile(Base):
    _attrs = dict(lines = Attr(List((Line, Empty, Comment))))
    _opts = dict(init_validate = True,
                 args = ('lines',))

    @init_hook
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
        self._update()

    def comment_address(self, address):
        for line in self.addrs[address]:
            line.is_comment = True
        self._update()

    def uncomment_host(self, name):
        self._update()

    def uncomment_address(self, address):
        for line in self.caddrs[address]:
            line.is_comment = False
        self._update()

    def remove_address(self, address, comments=False):
        for line in self.addrs[address]:
            self.lines.remove(line)
        if comments:
            for line in self.caddrs[address]:
                self.lines.remove(line)
        self._update()
                
    def update_address(self, old_address, new_address):
        self._update()

    def set_host(self, name, address):
        self._update()

    def remove_host(self, name, address):
        self._update()

    def update_host(self, name, address):
        self._update()

    def update(self, other, comments=False):
        self._update()

    def validate(self):
        super(HostsFile, self).validate()

        for line in self.lines:
            line.validate()


#-------------------------------------------------------------------------------
