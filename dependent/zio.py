#!/usr/bin/env python2
# ===============================================================================
# The Star And Thank Author License (SATA)
# 
# Copyright (c) 2014 zTrix(i@ztrix.me)
# 
# Project Url: https://github.com/zTrix/zio
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software. 
# 
# And wait, the most important, you shall star/+1/like the project(s) in project url 
# section above first, and then thank the author(s) in Copyright section. 
# 
# Here are some suggested ways:
# 
# - Email the authors a thank-you letter, and make friends with him/her/them.
# - Report bugs or issues.
# - Tell friends what a wonderful project this is.
# - And, sure, you can just express thanks in your mind without telling the world.
# 
# Contributors of this project by forking have the option to add his/her name and 
# forked project url at copyright and project url sections, but shall not delete 
# or modify anything else in these two sections.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
# ===============================================================================
__version__ = "1.0.3"
__project__ = "https://github.com/zTrix/zio"

import struct, socket, os, sys, time, re, select, errno, signal, datetime, inspect, atexit

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

try:
    from termcolor import colored
except:
    # if termcolor import failed, use the following v1.1.0 source code of termcolor here
    # since termcolor use MIT license, SATA license above should be OK
    ATTRIBUTES = dict(
        list(zip(['bold', 'dark', '', 'underline', 'blink', '', 'reverse', 'concealed'], list(range(1, 9)))))
    del ATTRIBUTES['']
    HIGHLIGHTS = dict(list(
        zip(['on_grey', 'on_red', 'on_green', 'on_yellow', 'on_blue', 'on_magenta', 'on_cyan', 'on_white'],
            list(range(40, 48)))))
    COLORS = dict(
        list(zip(['grey', 'red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white', ], list(range(30, 38)))))
    RESET = '\033[0m'

    def colored(text, color=None, on_color=None, attrs=None):
        fmt_str = '\033[%dm%s'
        if color is not None: text = fmt_str % (COLORS[color], text)
        if on_color is not None: text = fmt_str % (HIGHLIGHTS[on_color], text)
        if attrs is not None:
            for attr in attrs:
                text = fmt_str % (ATTRIBUTES[attr], text)

        text += RESET
        return text

__all__ = ['stdout', 'log', 'l8', 'b8', 'l16', 'b16', 'l32', 'b32', 'l64', 'b64', 'zio', 'EOF', 'TIMEOUT', 'SOCKET',
           'PROCESS', 'REPR', 'EVAL', 'HEX', 'UNHEX', 'BIN', 'UNBIN', 'RAW', 'NONE', 'COLORED', 'PIPE', 'TTY',
           'TTY_RAW', 'cmdline']


def stdout(s, color=None, on_color=None, attrs=None):
    if not color:
        sys.stdout.write(s)
    else:
        sys.stdout.write(colored(s, color, on_color, attrs))
    sys.stdout.flush()


def log(s, color=None, on_color=None, attrs=None, new_line=True, timestamp=False, f=sys.stderr):
    if timestamp is True:
        now = datetime.datetime.now().strftime('[%Y-%m-%d_%H:%M:%S]')
    elif timestamp is False:
        now = None
    elif timestamp:
        now = timestamp
    if not color:
        s = str(s)
    else:
        s = colored(str(s), color, on_color, attrs)
    if now:
        f.write(now)
        f.write(' ')
    f.write(s)
    if new_line:
        f.write('\n')
    f.flush()


def _lb_wrapper(func):
    endian = func.func_name[0] == 'l' and '<' or '>'
    bits = int(func.func_name[1:])
    pfs = {8: 'B', 16: 'H', 32: 'I', 64: 'Q'}

    def wrapper(*args):
        ret = []
        join = False
        for i in args:
            if isinstance(i, (int, long)):
                join = True
                v = struct.pack(endian + pfs[bits], i % (1 << bits))
                ret.append(v)
            else:
                if not i:
                    ret.append(None)
                else:
                    v = struct.unpack(endian + pfs[bits] * (len(i) * 8 / bits), i)
                    ret += v
        if join:
            return ''.join(ret)
        elif len(ret) == 1:
            return ret[0]
        elif len(ret) == 0:  # all of the input are empty strings
            return None
        else:
            return ret

    wrapper.func_name = func.func_name
    return wrapper


@_lb_wrapper
def l8(*args): pass


@_lb_wrapper
def b8(*args): pass


@_lb_wrapper
def l16(*args): pass


@_lb_wrapper
def b16(*args): pass


@_lb_wrapper
def l32(*args): pass


@_lb_wrapper
def b32(*args): pass


@_lb_wrapper
def l64(*args): pass


@_lb_wrapper
def b64(*args): pass


class EOF(Exception):
    """Raised when EOF is read from child or socket.
    This usually means the child has exited or socket shutdown at remote end"""


class TIMEOUT(Exception):
    """Raised when a read timeout exceeds the timeout. """


def COLORED(f, color='cyan', on_color=None, attrs=None): return lambda s: colored(f(s), color, on_color, attrs)


def REPR(s): return repr(str(s)) + '\r\n'


def EVAL(s):  # now you are not worried about pwning yourself
    st = 0  # 0 for normal, 1 for escape, 2 for \xXX
    ret = []
    i = 0
    while i < len(s):
        if st == 0:
            if s[i] == '\\':
                st = 1
            else:
                ret.append(s[i])
        elif st == 1:
            if s[i] in ('"', "'", "\\", "t", "n", "r"):
                if s[i] == 't':
                    ret.append('\t')
                elif s[i] == 'n':
                    ret.append('\n')
                elif s[i] == 'r':
                    ret.append('\r')
                else:
                    ret.append(s[i])
                st = 0
            elif s[i] == 'x':
                st = 2
            else:
                raise Exception('invalid repr of str %s' % s)
        else:
            num = int(s[i:i + 2], 16)
            assert 0 <= num < 256
            ret.append(chr(num))
            st = 0
            i += 1
        i += 1
    return ''.join(ret)


def HEX(s): return str(s).encode('hex') + '\r\n'


def UNHEX(s): s = str(s).strip(); return (len(s) % 2 and '0' + s or s).decode(
    'hex')  # hex-strings with odd length are now acceptable


def BIN(s): return ''.join([format(ord(x), '08b') for x in str(s)]) + '\r\n'


def UNBIN(s): s = str(s).strip(); return ''.join([chr(int(s[x:x + 8], 2)) for x in xrange(0, len(s), 8)])


def RAW(s): return str(s)


def NONE(s): return ''


class zio(object):
    def __init__(self, target, print_read=RAW, print_write=RAW, timeout=8, ignorecase=False):
        """
        zio is an easy-to-use io library for pwning development, supporting an unified interface for local process pwning and remote tcp socket io

        example:

        io = zio(('localhost', 80))
        io = zio(socket.create_connection(('127.0.0.1', 80)))
        io = zio('ls -l')
        io = zio(['ls', '-l'])

        params:
            print_read = bool, if true, print all the data read from target
            print_write = bool, if true, print all the data sent out
        """

        if not target:
            raise Exception('socket not provided for zio, try zio("ls -l")')

        self.target = target
        self.print_read = print_read
        self.print_write = print_write

        if isinstance(timeout, (int, long)) and timeout > 0:
            self.timeout = timeout
        else:
            self.timeout = 8

        self.flag_eof = False
        self.closed = True

        self.ignorecase = ignorecase

        self.buffer = str()

        if isinstance(self.target, socket.socket):
            self.sock = self.target
            self.name = repr(self.target)
        else:
            self.sock = socket.create_connection(self.target, self.timeout)
            self.name = '<socket ' + self.target[0] + ':' + str(self.target[1]) + '>'
        self.rfd = self.wfd = self.sock.fileno()
        self.closed = False


    @property
    def print_read(self):
        return self._print_read and (self._print_read is not NONE)

    @print_read.setter
    def print_read(self, value):
        if value is True:
            self._print_read = RAW
        elif value is False:
            self._print_read = NONE
        elif callable(value):
            self._print_read = value
        else:
            raise Exception('bad print_read value')

        assert callable(self._print_read) and len(inspect.getargspec(self._print_read).args) == 1

    @property
    def print_write(self):
        return self._print_write and (self._print_write is not NONE)

    @print_write.setter
    def print_write(self, value):
        if value is True:
            self._print_write = RAW
        elif value is False:
            self._print_write = NONE
        elif callable(value):
            self._print_write = value
        else:
            raise Exception('bad print_write value')

        assert callable(self._print_write) and len(inspect.getargspec(self._print_write).args) == 1


    def fileno(self):
        '''This returns the file descriptor of the pty for the child.
        '''
        return self.sock.fileno()

    def __str__(self):
        ret = ['name: %s' % self.name,
               'timeout: %f' % self.timeout,
               'write-fd: %d' % (isinstance(self.wfd, (int, long)) and self.wfd or self.fileno()),
               'read-fd: %d' % (isinstance(self.rfd, (int, long)) and self.rfd or self.fileno()),
               'buffer(last 100 chars): %r' % (self.buffer[-100:]),
               'eof: %s' % self.flag_eof]
        return '\n'.join(ret)

    def eof(self):

        '''This returns True if the EOF exception was ever raised.
        '''

        return self.flag_eof


    def isalive(self):

        '''This tests if the child process is running or not. This is
        non-blocking. If the child was terminated then this will read the
        exit code or signalstatus of the child. This returns True if the child
        process appears to be running or False if not. It can take literally
        SECONDS for Solaris to return the right status. '''

        return not self.flag_eof


    def interact(self, escape_character=chr(29), input_filter=None, output_filter=None, raw_rw=True):
        self.print_write = NONE
        """Multithreaded version of interact()."""
        import thread

        thread.start_new_thread(self.listener, ())
        while not self.closed:
            line = sys.stdin.readline()
            if not line:
                break
            self.write(line)

    def listener(self):
        """Helper for mt_interact() -- this executes in the other thread."""
        while self.isalive():
            try:
                self.read_until_timeout(10)
            except EOF:
                print '*** Connection closed by remote host ***'
                return

    def flush(self):
        """
        just keep to be a file-like object
        """
        pass

    def __select(self, iwtd, owtd, ewtd, timeout=None):

        '''This is a wrapper around select.select() that ignores signals. If
        select.select raises a select.error exception and errno is an EINTR
        error then it is ignored. Mainly this is used to ignore sigwinch
        (terminal resize). '''

        # if select() is interrupted by a signal (errno==EINTR) then
        # we loop back and enter the select() again.
        if timeout is not None:
            end_time = time.time() + timeout
        while True:
            try:
                return select.select(iwtd, owtd, ewtd, timeout)
            except select.error:
                err = sys.exc_info()[1]
                if err[0] == errno.EINTR:
                    # if we loop back we have to subtract the
                    # amount of time we already waited.
                    if timeout is not None:
                        timeout = end_time - time.time()
                        if timeout < 0:
                            return ([], [], [])
                else:
                    # something else caused the select.error, so
                    # this actually is an exception.
                    raise

    def writelines(self, sequence):
        n = 0
        for s in sequence:
            n += self.writeline(s)
        return n

    def writeline(self, s=''):
        return self.write(s + os.linesep)

    def write(self, s):
        if not s: return 0
        if self.print_write: stdout(self._print_write(s))
        self.sock.sendall(s)
        return len(s)

    def end(self, force_close=False):
        '''
        end of writing stream, but we can still read
        '''
        self.sock.shutdown(socket.SHUT_WR)

    def close(self, force=True):
        '''
        close and clean up, nothing can and should be done after closing
        '''
        if self.closed:
            return
        if self.sock:
            self.sock.close()
        self.sock = None


    def read(self, size=None, timeout=-1):
        if size == 0:
            return str()
        elif size < 0 or size is None:
            self.read_loop(searcher_re(self.compile_pattern_list(EOF)), timeout=timeout)
            return self.before

        cre = re.compile('.{%d}' % size, re.DOTALL)
        index = self.read_loop(searcher_re(self.compile_pattern_list([cre, EOF])), timeout=timeout)
        if index == 0:
            assert self.before == ''
            return self.after
        return self.before

    def read_until_timeout(self, timeout=0.05):
        try:
            incoming = self.buffer
            while True:
                c = self.read_nonblocking(2048, timeout)
                incoming = incoming + c
        except EOF:
            err = sys.exc_info()[1]
            self.buffer = str()
            self.before = str()
            self.after = EOF
            self.match = incoming
            self.match_index = None
            raise EOF(str(err) + '\n' + str(self))
        except TIMEOUT:
            self.buffer = str()
            self.before = str()
            self.after = TIMEOUT
            self.match = incoming
            self.match_index = None
            return incoming
        except:
            self.before = str()
            self.after = None
            self.match = incoming
            self.match_index = None
            raise

    read_eager = read_until_timeout

    def readable(self):
        return self.__select([self.rfd], [], [], 0) == ([self.rfd], [], [])

    def readline(self, size=-1):
        if size == 0:
            return str()
        lineseps = [b'\r\n', b'\n', EOF]
        index = self.read_loop(searcher_re(self.compile_pattern_list(lineseps)))
        if index < 2:
            return self.before + lineseps[index]
        else:
            return self.before

    read_line = readline

    def readlines(self, sizehint=-1):
        lines = []
        while True:
            line = self.readline()
            if not line:
                break
            lines.append(line)
        return lines

    def read_until(self, pattern_list, timeout=-1, searchwindowsize=None):
        if (isinstance(pattern_list, basestring) or
                    pattern_list in (TIMEOUT, EOF)):
            pattern_list = [pattern_list]

        def prepare_pattern(pattern):
            if pattern in (TIMEOUT, EOF):
                return pattern
            if isinstance(pattern, basestring):
                return pattern
            self._pattern_type_err(pattern)

        try:
            pattern_list = iter(pattern_list)
        except TypeError:
            self._pattern_type_err(pattern_list)
        pattern_list = [prepare_pattern(p) for p in pattern_list]
        matched = self.read_loop(searcher_string(pattern_list), timeout, searchwindowsize)
        ret = self.before
        if isinstance(self.after, basestring):
            ret += self.after  # after is the matched string, before is the string before this match
        return ret  # be compatible with telnetlib.read_until

    def read_until_re(self, pattern, timeout=-1, searchwindowsize=None):
        compiled_pattern_list = self.compile_pattern_list(pattern)
        matched = self.read_loop(searcher_re(compiled_pattern_list), timeout, searchwindowsize)
        ret = self.before
        if isinstance(self.after, basestring):
            ret += self.after
        return ret

    def read_loop(self, searcher, timeout=-1, searchwindowsize=None):

        '''This is the common loop used inside expect. The 'searcher' should be
        an instance of searcher_re or searcher_string, which describes how and
        what to search for in the input.

        See expect() for other arguments, return value and exceptions. '''

        self.searcher = searcher

        if timeout == -1:
            timeout = self.timeout
        if timeout is not None:
            end_time = time.time() + timeout

        try:
            incoming = self.buffer
            freshlen = len(incoming)
            while True:
                # Keep reading until exception or return.
                index = searcher.search(incoming, freshlen, searchwindowsize)
                if index >= 0:
                    self.buffer = incoming[searcher.end:]
                    self.before = incoming[: searcher.start]
                    self.after = incoming[searcher.start: searcher.end]
                    self.match = searcher.match  # should be equal to self.after now if not (EOF or TIMEOUT)
                    self.match_index = index
                    return self.match_index
                # No match at this point
                if (timeout is not None) and (timeout < 0):
                    raise TIMEOUT('Timeout exceeded in expect_any().')
                # Still have time left, so read more data
                c = self.read_nonblocking(2048, timeout)
                freshlen = len(c)
                time.sleep(0.0001)
                incoming = incoming + c
                if timeout is not None:
                    timeout = end_time - time.time()
        except EOF:
            err = sys.exc_info()[1]
            self.buffer = str()
            self.before = incoming
            self.after = EOF
            index = searcher.eof_index
            if index >= 0:
                self.match = EOF
                self.match_index = index
                return self.match_index
            else:
                self.match = None
                self.match_index = None
                raise EOF(str(err) + '\n' + str(self))
        except TIMEOUT:
            err = sys.exc_info()[1]
            self.buffer = incoming
            self.before = incoming
            self.after = TIMEOUT
            index = searcher.timeout_index
            if index >= 0:
                self.match = TIMEOUT
                self.match_index = index
                return self.match_index
            else:
                self.match = None
                self.match_index = None
                raise TIMEOUT(str(err) + '\n' + str(self))
        except:
            self.before = incoming
            self.after = None
            self.match = None
            self.match_index = None
            raise

    def _pattern_type_err(self, pattern):
        raise TypeError('got {badtype} ({badobj!r}) as pattern, must be one'
                        ' of: {goodtypes}, pexpect.EOF, pexpect.TIMEOUT' \
                        .format(badtype=type(pattern),
                                badobj=pattern,
                                goodtypes=', '.join([str(ast) \
                                                     for ast in basestring])
                                )
                        )

    def compile_pattern_list(self, patterns):

        '''This compiles a pattern-string or a list of pattern-strings.
        Patterns must be a StringType, EOF, TIMEOUT, SRE_Pattern, or a list of
        those. Patterns may also be None which results in an empty list (you
        might do this if waiting for an EOF or TIMEOUT condition without
        expecting any pattern).

        This is used by expect() when calling expect_list(). Thus expect() is
        nothing more than::

             cpl = self.compile_pattern_list(pl)
             return self.expect_list(cpl, timeout)

        If you are using expect() within a loop it may be more
        efficient to compile the patterns first and then call expect_list().
        This avoid calls in a loop to compile_pattern_list()::

             cpl = self.compile_pattern_list(my_pattern)
             while some_condition:
                ...
                i = self.expect_list(clp, timeout)
                ...
        '''

        if patterns is None:
            return []
        if not isinstance(patterns, list):
            patterns = [patterns]

        # Allow dot to match \n
        compile_flags = re.DOTALL
        if self.ignorecase:
            compile_flags = compile_flags | re.IGNORECASE
        compiled_pattern_list = []
        for idx, p in enumerate(patterns):
            if isinstance(p, basestring):
                compiled_pattern_list.append(re.compile(p, compile_flags))
            elif p is EOF:
                compiled_pattern_list.append(EOF)
            elif p is TIMEOUT:
                compiled_pattern_list.append(TIMEOUT)
            elif isinstance(p, type(re.compile(''))):
                compiled_pattern_list.append(p)
            else:
                self._pattern_type_err(p)
        return compiled_pattern_list

    def _read(self, size):
        try:
            return self.sock.recv(size)
        except socket.error, err:
            if err.args[0] == errno.ECONNRESET:
                raise EOF('Connection reset by peer')
            raise err

    def _write(self, s):
        self.sock.sendall(s)
        return len(s)

    def read_nonblocking(self, size=1, timeout=-1):
        '''This reads at most size characters from the child application. It
        includes a timeout. If the read does not complete within the timeout
        period then a TIMEOUT exception is raised. If the end of file is read
        then an EOF exception will be raised.

        If timeout is None then the read may block indefinitely.
        If timeout is -1 then the self.timeout value is used. If timeout is 0
        then the child is polled and if there is no data immediately ready
        then this will raise a TIMEOUT exception.

        The timeout refers only to the amount of time to read at least one
        character. This is not effected by the 'size' parameter, so if you call
        read_nonblocking(size=100, timeout=30) and only one character is
        available right away then one character will be returned immediately.
        It will not wait for 30 seconds for another 99 characters to come in.

        This is a wrapper around os.read(). It uses select.select() to
        implement the timeout. '''

        if self.closed:
            raise ValueError('I/O operation on closed file.')

        if timeout == -1:
            timeout = self.timeout

        # Note that some systems such as Solaris do not give an EOF when
        # the child dies. In fact, you can still try to read
        # from the child_fd -- it will block forever or until TIMEOUT.
        # For this case, I test isalive() before doing any reading.
        # If isalive() is false, then I pretend that this is the same as EOF.
        if not self.isalive():
            # timeout of 0 means "poll"
            r, w, e = self.__select([self.rfd], [], [], 0)
            if not r:
                self.flag_eof = True
                raise EOF('End Of File (EOF). Braindead platform.')

        if timeout is not None and timeout > 0:
            end_time = time.time() + timeout
        else:
            end_time = float('inf')

        readfds = [self.rfd]

        while True:
            now = time.time()
            if now > end_time: break
            if timeout is not None and timeout > 0:
                timeout = end_time - now
            r, w, e = self.__select(readfds, [], [], timeout)

            if not r:
                if not self.isalive():
                    # Some platforms, such as Irix, will claim that their
                    # processes are alive; timeout on the select; and
                    # then finally admit that they are not alive.
                    self.flag_eof = True
                    raise EOF('End of File (EOF). Very slow platform.')
                else:
                    continue

            if self.rfd in r:
                try:
                    s = self._read(size)
                    if s and self.print_read: stdout(self._print_read(s))
                except OSError:
                    # Linux does this
                    self.flag_eof = True
                    raise EOF('End Of File (EOF). Exception style platform.')
                if s == b'':
                    # BSD style
                    self.flag_eof = True
                    raise EOF('End Of File (EOF). Empty string style platform.')

                return s

        raise TIMEOUT('Timeout exceeded. size to read: %d' % size)
        # raise Exception('Reached an unexpected state, timeout = %d' % (timeout))

    def _not_impl(self):
        raise NotImplementedError("Not Implemented")

    # apis below
    read_after = read_before = read_between = read_range = _not_impl


class searcher_string(object):
    '''This is a plain string search helper for the spawn.expect_any() method.
    This helper class is for speed. For more powerful regex patterns
    see the helper class, searcher_re.

    Attributes:

        eof_index     - index of EOF, or -1
        timeout_index - index of TIMEOUT, or -1

    After a successful match by the search() method the following attributes
    are available:

        start - index into the buffer, first byte of match
        end   - index into the buffer, first byte after match
        match - the matching string itself

    '''

    def __init__(self, strings):

        '''This creates an instance of searcher_string. This argument 'strings'
        may be a list; a sequence of strings; or the EOF or TIMEOUT types. '''

        self.eof_index = -1
        self.timeout_index = -1
        self._strings = []
        for n, s in enumerate(strings):
            if s is EOF:
                self.eof_index = n
                continue
            if s is TIMEOUT:
                self.timeout_index = n
                continue
            self._strings.append((n, s))

    def __str__(self):

        '''This returns a human-readable string that represents the state of
        the object.'''

        ss = [(ns[0], '    %d: "%s"' % ns) for ns in self._strings]
        ss.append((-1, 'searcher_string:'))
        if self.eof_index >= 0:
            ss.append((self.eof_index, '    %d: EOF' % self.eof_index))
        if self.timeout_index >= 0:
            ss.append((self.timeout_index,
                       '    %d: TIMEOUT' % self.timeout_index))
        ss.sort()
        ss = list(zip(*ss))[1]
        return '\n'.join(ss)

    def search(self, buffer, freshlen, searchwindowsize=None):

        '''This searches 'buffer' for the first occurence of one of the search
        strings.  'freshlen' must indicate the number of bytes at the end of
        'buffer' which have not been searched before. It helps to avoid
        searching the same, possibly big, buffer over and over again.

        See class spawn for the 'searchwindowsize' argument.

        If there is a match this returns the index of that string, and sets
        'start', 'end' and 'match'. Otherwise, this returns -1. '''

        first_match = None

        # 'freshlen' helps a lot here. Further optimizations could
        # possibly include:
        #
        # using something like the Boyer-Moore Fast String Searching
        # Algorithm; pre-compiling the search through a list of
        # strings into something that can scan the input once to
        # search for all N strings; realize that if we search for
        # ['bar', 'baz'] and the input is '...foo' we need not bother
        # rescanning until we've read three more bytes.
        #
        # Sadly, I don't know enough about this interesting topic. /grahn

        for index, s in self._strings:
            if searchwindowsize is None:
                # the match, if any, can only be in the fresh data,
                # or at the very end of the old data
                offset = -(freshlen + len(s))
            else:
                # better obey searchwindowsize
                offset = -searchwindowsize
            n = buffer.find(s, offset)
            if n >= 0 and (first_match is None or n < first_match):
                first_match = n
                best_index, best_match = index, s
        if first_match is None:
            return -1
        self.match = best_match
        self.start = first_match
        self.end = self.start + len(self.match)
        return best_index


class searcher_re(object):
    '''This is regular expression string search helper for the
    spawn.expect_any() method. This helper class is for powerful
    pattern matching. For speed, see the helper class, searcher_string.

    Attributes:

        eof_index     - index of EOF, or -1
        timeout_index - index of TIMEOUT, or -1

    After a successful match by the search() method the following attributes
    are available:

        start - index into the buffer, first byte of match
        end   - index into the buffer, first byte after match
        match - the re.match object returned by a succesful re.search

    '''

    def __init__(self, patterns):

        '''This creates an instance that searches for 'patterns' Where
        'patterns' may be a list or other sequence of compiled regular
        expressions, or the EOF or TIMEOUT types.'''

        self.eof_index = -1
        self.timeout_index = -1
        self._searches = []
        for n, s in zip(list(range(len(patterns))), patterns):
            if s is EOF:
                self.eof_index = n
                continue
            if s is TIMEOUT:
                self.timeout_index = n
                continue
            self._searches.append((n, s))

    def __str__(self):

        '''This returns a human-readable string that represents the state of
        the object.'''

        # ss = [(n, '    %d: re.compile("%s")' %
        # (n, repr(s.pattern))) for n, s in self._searches]
        ss = list()
        for n, s in self._searches:
            try:
                ss.append((n, '    %d: re.compile("%s")' % (n, s.pattern)))
            except UnicodeEncodeError:
                # for test cases that display __str__ of searches, dont throw
                # another exception just because stdout is ascii-only, using
                # repr()
                ss.append((n, '    %d: re.compile(%r)' % (n, s.pattern)))
        ss.append((-1, 'searcher_re:'))
        if self.eof_index >= 0:
            ss.append((self.eof_index, '    %d: EOF' % self.eof_index))
        if self.timeout_index >= 0:
            ss.append((self.timeout_index, '    %d: TIMEOUT' %
                       self.timeout_index))
        ss.sort()
        ss = list(zip(*ss))[1]
        return '\n'.join(ss)

    def search(self, buffer, freshlen, searchwindowsize=None):

        '''This searches 'buffer' for the first occurence of one of the regular
        expressions. 'freshlen' must indicate the number of bytes at the end of
        'buffer' which have not been searched before.

        See class spawn for the 'searchwindowsize' argument.

        If there is a match this returns the index of that string, and sets
        'start', 'end' and 'match'. Otherwise, returns -1.'''

        first_match = None
        # 'freshlen' doesn't help here -- we cannot predict the
        # length of a match, and the re module provides no help.
        if searchwindowsize is None:
            searchstart = 0
        else:
            searchstart = max(0, len(buffer) - searchwindowsize)
        for index, s in self._searches:
            match = s.search(buffer, searchstart)
            if match is None:
                continue
            n = match.start()
            if first_match is None or n < first_match:
                first_match = n
                the_match = match
                best_index = index
        if first_match is None:
            return -1
        self.start = first_match
        self.match = the_match
        self.end = self.match.end()
        return best_index


def hostport_tuple(target):
    def _check_host(host):
        try:
            socket.gethostbyname(host)
            return True
        except:
            return False

    return type(target) == tuple and len(target) == 2 and isinstance(target[1], (int, long)) and target[1] >= 0 and \
           target[1] < 65536 and _check_host(target[0])


# vi:set et ts=4 sw=4 ft=python :
