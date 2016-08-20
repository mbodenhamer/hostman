import re
from syn.five import STR
from syn.type import List
from syn.base_utils import implies
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


class Empty(Base):
    def to_string(self):
        return ''


class Comment(Base):
    _attrs = dict(text = Attr(str, '', doc='Text of the comment'))
    _opts = dict(args = ('text',))

    @init_hook
    def _update_names(self):
        self.names = self.text.split()

    def _update_text(self):
        self.text = ' '.join(self.names)

    def add_name(self, name):
        self.names.append(name)
        self._update_text()

    def remove_name(self, name):
        self.names.remove(name)
        self._update_text()

    def to_string(self):
        if not self.text:
            return ''
        return '#{}'.format(self.text)


class Line(Base):
    _attrs = dict(address = Attr(STR, doc='The IP address'),
                  names = Attr(List(STR), doc='A list of hostnames'),
                  comment = Attr(Comment, '', "Content of this line's comment"),
                  is_comment = Attr(bool, False, 'True if this line is '
                                    'completely a comment'),
                  was_made_comment = Attr(bool, False, internal=True))
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

        return cls(address, names, Comment(comment), is_comment)

    def _comment_check(self):
        if self.names:
            if self.was_made_comment and self.is_comment:
                self.is_comment = False
                self.was_made_comment = False
            
        if not self.names:
            self.is_comment = True
            self.was_made_comment = True
        

    def add_host(self, name):
        if name not in self.names:
            self.names.append(name)
        self._comment_check()

    def is_host_commented(self, name):
        if name in self.names:
            return False
        return name in self.comment.names

    def comment_host(self, name):
        self.comment.add_name(name)
        self.names.remove(name)
        self._comment_check()

    def remove_host(self, name):
        self.names.remove(name)
        self._comment_check()

    def uncomment_host(self, name):
        self.comment.remove_name(name)
        self.names.append(name)
        self._comment_check()

    def to_string(self):
        comment = self.comment.to_string()
        comment = ' ' + comment if comment else ''
        return '{}{}\t{}{}'.format('# ' if self.is_comment else '',
                                   self.address,
                                   ' '.join(self.names),
                                   comment)

    def validate(self):
        super(Line, self).validate()

        if not is_address(self.address):
            raise ValueError("Attribute 'address' must be valid IP address")
        
        if not len(self.names) >= 1 and not self.is_comment:
            raise ValueError("Attribute 'names' must have at least 1 member")

        for name in self.names:
            if not is_name(name):
                raise ValueError("Invalid hostname: {}".format(name))


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
    def from_text(cls, text):
        lines = text.split('\n')
        return cls([Line.from_line(line) for line in lines])

    @classmethod
    def read(cls, fil):
        return cls.from_text(fil.read())

    def to_text(self):
        lines = [line.to_string() for line in self.lines]
        return '\n'.join(lines)

    def write(self, fil):
        fil.write(self.to_text())

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
        self.hosts[name].comment_host(name)
        self._update()

    def comment_address(self, address):
        for line in self.addrs[address]:
            line.is_comment = True
        self._update()

    def uncomment_host(self, name):
        self.chosts[name].uncomment_host(name)
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
        for line in self.addrs[old_address]:
            line.address = new_address
        for line in self.caddrs[old_address]:
            line.address = new_address
        self._update()
        self.validate()

    def set_host(self, name, address):
        line = self.hosts.get(name, Line(address, [name]))
        line.add_host(name)
        if line not in self.lines:
            self.lines.append(line)
        self._update()

    def remove_host(self, name, address=None):
        self.hosts[name].remove
        self._update()

    def merge(self, other, merge_comments=True):
        for oline in other:
            lines = [line for line in self.line 
                     if line.address == other.address]
            if not lines:
                self.lines.append(oline)
            else:
                old_names = []
                for name in oline.names:
                    if any(name in line.names for line in lines):
                        old_names.append(name)
                for name in old_names:
                    oline.names.remove(name)

                for name in oline.names:
                    self.set_host(name, oline.address)

                if merge_comments:
                    self.addrs[oline.address][0].comment.names.extend(
                        oline.comment.names)

        self._update()

    def validate(self):
        super(HostsFile, self).validate()

        for line in self.lines:
            line.validate()


#-------------------------------------------------------------------------------
