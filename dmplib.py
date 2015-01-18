import struct, time

class _Struct:
    def __init__(self, fmt, extra, **kw):
        self._fmt = fmt
        self._kw = kw
        self._extra = extra

    def __getattr__(self, name):
        return self._kw[name]

    def __str__(self):
        return self._fmt.repr(self)

    def __repr__(self):
        return self._fmt.repr(self)

    def pack(self):
        return self._fmt.pack(self)

    def clone(self):
        return _Struct(self._fmt, self._extra, **dict(self._kw))

_struct_repo = {}

class _StructWithNames:
    def __init__(self, name, fmt_prefix, *names):
        self.name = name
        split_names = [name.split(':', 1) for name in names]

        self.names = [name for name, _ in split_names]
        self.types = [_struct_repo.get(t, t) for _, t in split_names]

        member_map = {}
        member_sers = []
        self.defaults = {}

        p = 0
        fmts = []
        for name, t in zip(self.names, self.types):
            if type(t) == str:
                self.defaults[name] = 0
                fmts.append(t)
                member_map[name] = lambda r, p=p: r[p]
                p += 1
            else:
                self.defaults[name] = t()
                fmts.append(t.fmt)
                member_map[name] = lambda r, p=p, t=t: t.unpack_tuple(r[p:p+t.tuple_len])
                p += t.tuple_len

        self._member_constrs = member_map
        self.fmt = ''.join(fmts)
        fmt = fmt_prefix + self.fmt
        self._struct = struct.Struct(fmt)
        self.size = self._struct.size
        self.tuple_len = p

    def update_tuple(self, t, s):
        for name, kind in zip(self.names, self.types):
            if type(kind) == str:
                t.append(getattr(s, name))
            else:
                kind.update_tuple(t, getattr(s, name))

    def pack(self, s):
        t = []
        self.update_tuple(t, s)
        return self._struct.pack(*t) + s._extra

    def unpack(self, string):
        r = self._struct.unpack(string)
        return self.unpack_tuple(r)

    def unpack_all(self, string):
        r = self._struct.unpack(string[:self.size])
        return self.unpack_tuple(r, string[self.size:])

    def unpack_tuple(self, r, extra=''):
        if len(r) != self.tuple_len:
            raise RuntimeError('XXX')

        res = {}
        for k, v in self._member_constrs.iteritems():
            res[k] = v(r)

        return _Struct(self, extra, **res)

    def repr(self, s):
        return '%s(%s)' % (self.name, ', '.join('%s=%r' % (name, getattr(s, name)) for name in self.names))

    def __call__(self, *args, **kws):
        kw = dict(self.defaults)
        kw.update(kws)
        for name, arg in zip(self.names, args):
            kw[name] = arg
        return _Struct(self, '', **kw)
        
    def read(self, fp, offset=None, cnt=None):
        size = self.size

        def read_one():
            if offset is not None:
                fp.seek(offset)
            buf = fp.read(size)
            return self.unpack(buf)

        if cnt is None:
            return read_one()

        res = []
        for i in xrange(cnt):
            res.append(read_one())
            if offset is not None:
                offset += size
        return res

def read_struct(fp, fmt):
    s = struct.Struct(fmt)
    buf = fp.read(s.size)
    return s.unpack(buf)

def define_struct(name, fmt_prefix, *names):
    s = _StructWithNames(name, fmt_prefix, *names)
    _struct_repo[name] = s
    globals()[name] = s
    return s

define_struct('MINIDUMP_HEADER', '<',
    'Signature:4s',
    'Version:I',
    'NumberOfStreams:I',
    'StreamDirectoryRva:I',
    'CheckSum:I',
    'TimeDateStamp:I',
    'Flags:Q'
    )

define_struct('MINIDUMP_LOCATION_DESCRIPTOR', '<',
    'DataSize:I',
    'RVA:I'
    )

define_struct('MINIDUMP_DIRECTORY', '<',
    'StreamType:I',
    'Location:MINIDUMP_LOCATION_DESCRIPTOR'
    )

define_struct('MINIDUMP_MEMORY_DESCRIPTOR', '<',
    'StartOfMemoryRange:Q',
    'Memory:MINIDUMP_LOCATION_DESCRIPTOR'
    )

define_struct('MINIDUMP_MEMORY64_LIST', '<',
    'NumberOfMemoryRanges:Q',
    'BaseRva:Q'
    )

define_struct('MINIDUMP_MEMORY_DESCRIPTOR64', '<',
    'StartOfMemoryRange:Q',
    'DataSize:Q'
    )

define_struct('VS_FIXEDFILEINFO', '<',
    'dwSignature:I',
    'dwStrucVersion:I',
    'dwFileVersionMS:I',
    'dwFileVersionLS:I',
    'dwProductVersionMS:I',
    'dwProductVersionLS:I',
    'dwFileFlagsMask:I',
    'dwFileFlags:I',
    'dwFileOS:I',
    'dwFileType:I',
    'dwFileSubtype:I',
    'dwFileDateMS:I',
    'dwFileDateLS:I'
    )

define_struct('MINIDUMP_MODULE', '<',
    'BaseOfImage:Q',
    'SizeOfImage:I',
    'CheckSum:I',
    'TimeDateStamp:I',
    'ModuleNameRva:I',
    'VersionInfo:VS_FIXEDFILEINFO',
    'CvRecord:MINIDUMP_LOCATION_DESCRIPTOR',
    'MiscRecord:MINIDUMP_LOCATION_DESCRIPTOR',
    'Reserved0:Q',
    'Reserved1:Q'
    )

define_struct('MINIDUMP_THREAD', '<',
    'ThreadId:I',
    'SuspendCount:I',
    'PriorityClass:I',
    'Priority:I',
    'Teb:Q',
    'Stack:MINIDUMP_MEMORY_DESCRIPTOR',
    'ThreadContext:MINIDUMP_LOCATION_DESCRIPTOR',
    )

define_struct('MINIDUMP_SYSTEM_INFO', '<',
    'ProcessorArchitecture:H',
    'ProcessorLevel:H',
    'ProcessorRevision:H',
    'NumberOfProcessors:B',
    'ProductType:B',

    'MajorVersion:I',
    'MinorVersion:I',
    'BuildNumber:I',
    'PlatformId:I',

    'CSDVersionRva:I',

    'SuiteMask:H',
    'Reserved2:H'
    )

define_struct('MINIDUMP_UNLOADED_MODULE', '<',
    'BaseOfImage:Q',
    'SizeOfImage:I',
    'CheckSum:I',
    'TimeDateStamp:I',
    'ModuleNameRva:I'
    )

define_struct('MINIDUMP_UNLOADED_MODULE_LIST', '<',
    'SizeOfHeader:I',
    'SizeOfEntry:I',
    'NumberOfEntries:I'
    )

define_struct('MINIDUMP_HANDLE_DATA_STREAM', '<',
    'SizeOfHeader:I',
    'SizeOfDescriptor:I',
    'NumberOfDescriptors:I',
    'Reserved:I'
    )

define_struct('MINIDUMP_HANDLE_DESCRIPTOR', '<',
    'Handle:Q',
    'TypeNameRva:I',
    'ObjectNameRva:I',
    'Attributes:I',
    'GrantedAccess:I',
    'HandleCount:I',
    'PointerCount:I'
    )

UnusedStream               = 0
ReservedStream0            = 1
ReservedStream1            = 2
ThreadListStream           = 3
ModuleListStream           = 4
MemoryListStream           = 5
ExceptionStream            = 6
SystemInfoStream           = 7
ThreadExListStream         = 8
Memory64ListStream         = 9
CommentStreamA             = 10
CommentStreamW             = 11
HandleDataStream           = 12
FunctionTableStream        = 13
UnloadedModuleListStream   = 14
MiscInfoStream             = 15
MemoryInfoListStream       = 16
ThreadInfoListStream       = 17
HandleOperationListStream  = 18

MiniDumpNormal                          = 0x00000000
MiniDumpWithDataSegs                    = 0x00000001
MiniDumpWithFullMemory                  = 0x00000002
MiniDumpWithHandleData                  = 0x00000004
MiniDumpFilterMemory                    = 0x00000008
MiniDumpScanMemory                      = 0x00000010
MiniDumpWithUnloadedModules             = 0x00000020
MiniDumpWithIndirectlyReferencedMemory  = 0x00000040
MiniDumpFilterModulePaths               = 0x00000080
MiniDumpWithProcessThreadData           = 0x00000100
MiniDumpWithPrivateReadWriteMemory      = 0x00000200
MiniDumpWithoutOptionalData             = 0x00000400
MiniDumpWithFullMemoryInfo              = 0x00000800
MiniDumpWithThreadInfo                  = 0x00001000
MiniDumpWithCodeSegs                    = 0x00002000
MiniDumpWithoutAuxiliaryState           = 0x00004000
MiniDumpWithFullAuxiliaryState          = 0x00008000
MiniDumpWithPrivateWriteCopyMemory      = 0x00010000
MiniDumpIgnoreInaccessibleMemory        = 0x00020000
MiniDumpWithTokenInformation            = 0x00040000
MiniDumpWithModuleHeaders               = 0x00080000
MiniDumpFilterTriage                    = 0x00100000

class _Substream:
    def __init__(self, fp, offset, size):
        self.fp = fp
        self.offset = offset
        self.size = size
        self.pos = 0

    def seek(self, offset):
        self.pos = offset

    def read(self, size=None):
        self.fp.seek(self.offset + self.pos)
        rem = self.size - self.pos
        if size is None:
            size = rem

        res = self.fp.read(min(size, rem))
        self.pos += len(res)
        return res

class DumpStream:
    def __init__(self, kind, fp):
        self.kind = kind
        self.fp = fp

    def __repr__(self):
        return 'DumpStream(%r)' % self.kind

    def __str__(self):
        return repr(self)

class Dump:
    def __init__(self):
        self._fp = None
        self._dir = []

    def open(self, fp):
        self._fp = fp
        h = self._read(0, MINIDUMP_HEADER)
        if h.Signature != 'MDMP':
            raise RuntimeError('XXX invalid signature')
        self._dir = self._read(h.StreamDirectoryRva, MINIDUMP_DIRECTORY, h.NumberOfStreams)
        self._h = h

    def streams(self):
        return [DumpStream(entry.StreamType, _Substream(self._fp, entry.Location.RVA, entry.Location.DataSize))
            for entry in self._dir if entry.StreamType != UnusedStream]

    def timestamp(self):
        return self._h.TimeDateStamp

    def flags(self):
        return self._h.Flags

    def _read(self, offset, fmt, cnt=None):
        if type(fmt) == int:
            size = fmt
        else:
            size = fmt.size

        def read_one():
            self._fp.seek(offset)
            buf = self._fp.read(size)
            if type(fmt) == int:
                return buf
            return fmt.unpack(buf)

        if cnt is None:
            return read_one()

        res = []
        for i in xrange(cnt):
            res.append(read_one())
            offset += size
        return res

    def _read_array(self, offset, fmt, cnt):
        return [self._read(offset + fmt.size*p, fmt) for p in xrange(cnt)]

class DumpWriter:
    def __init__(self, fp, max_stream_cnt):
        self._h = MINIDUMP_HEADER(Signature='MDMP', Version=1618061203, StreamDirectoryRva=MINIDUMP_HEADER.size, TimeDateStamp=int(time.time()))
        self._fp = fp
        self._dir = []
        self._offset = MINIDUMP_HEADER.size + max_stream_cnt * MINIDUMP_DIRECTORY.size
        fp.seek(self._offset)

    def add_stream(self, kind, stream):
#        if type(stream) == str:
#            self._fp.write(stream)
#            stream_size += len(stream)
#        else:
#            while True:
#                buf = stream.read(1024*1024)
#                if len(buf) == 0:
#                    break
#                self._fp.write(buf)
#                stream_size += len(buf)

        if type(stream) != str:
            stream = stream.read()

        o = self.add_stream_placeholder(kind, len(stream))
        self.set_stream(o, stream)
        return o

    def add_stream_placeholder(self, kind, size):
        self._offset = (self._offset + 7) & ~7
        self._dir.append(MINIDUMP_DIRECTORY(kind, MINIDUMP_LOCATION_DESCRIPTOR(size, self._offset)))
        self._offset += size
        return self._dir[-1]

    def set_stream(self, o, data):
        assert o.Location.DataSize >= len(data)
        self._fp.seek(o.Location.RVA)
        self._fp.write(data)
        o.Location.DataSize = len(data)

    def stream_size(self, o):
        return o.Location.DataSize

    def stream_offset(self, o):
        return o.Location.RVA

    def timestamp(self, ts):
        self._h.TimeDateStamp = ts

    def flags(self, f):
        self._h.Flags = f

    def current_size(self):
        return self._offset

    def write_oob(self, data):
        if data is None:
            return MINIDUMP_LOCATION_DESCRIPTOR(0, 0)

        res = self._offset
        self._fp.seek(self._offset)
        self._fp.write(data)
        self._offset += len(data)
        return MINIDUMP_LOCATION_DESCRIPTOR(len(data), res)

    def close(self):
        self._seek(0)
        self._h.NumberOfStreams = len(self._dir)
        self._write(self._h)
        self._write(self._dir)

    def _seek(self, o):
        self._fp.seek(o)
        self._offset = o

    def _write(self, s):
        if type(s) == list:
            for m in s:
                self._write(m)
            return

        if type(s) != str:
            s = s.pack()

        self._fp.write(s)
        self._offset += len(s)
