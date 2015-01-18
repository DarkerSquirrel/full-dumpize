import sys, argparse, os.path
from dmplib import *

def fulldumpize(fin, fout):
    d = Dump()
    d.open(fin)
    streams = d.streams()

    dw = DumpWriter(fout, len(streams))
    dw.timestamp(d.timestamp())
    dw.flags(d.flags() & ~(MiniDumpWithDataSegs | MiniDumpWithIndirectlyReferencedMemory | MiniDumpWithPrivateReadWriteMemory | MiniDumpWithCodeSegs) | MiniDumpWithFullMemory)

    def load(d):
        if d.RVA == 0:
            return None
        fin.seek(d.RVA)
        return fin.read(d.DataSize)

    def load_str(rva):
        fin.seek(rva)
        length, = struct.unpack('<I', fin.read(4))
        buf = fin.read(length)
        return buf.decode('utf-16le')

    def make_str(s):
        buf = s.encode('utf-16le')
        return struct.pack('<I', len(buf)) + buf + '\x00\x00'

    mls = None
    mls64 = None
    for s in streams:
        if s.kind == Memory64ListStream:
            mls64 = s
            continue

        if s.kind == HandleDataStream:
            header = MINIDUMP_HANDLE_DATA_STREAM.read(s.fp, 0)
            if header.SizeOfDescriptor != MINIDUMP_HANDLE_DESCRIPTOR.size:
                continue

            entries = MINIDUMP_HANDLE_DESCRIPTOR.read(s.fp, header.SizeOfHeader, header.NumberOfDescriptors)
            o = dw.add_stream_placeholder(s.kind, s.fp.size)

            for e in entries:
                e.TypeNameRva = dw.write_oob(make_str(load_str(e.TypeNameRva))).RVA
                e.ObjectNameRva = dw.write_oob(make_str(load_str(e.ObjectNameRva))).RVA

            dw.set_stream(o, header.pack() + ''.join(e.pack() for e in entries))
            continue

        if s.kind == UnloadedModuleListStream:
            header = MINIDUMP_UNLOADED_MODULE_LIST.read(s.fp, 0)

            s.fp.seek(header.SizeOfHeader)
            entries = [MINIDUMP_UNLOADED_MODULE.unpack_all(s.fp.read(header.SizeOfEntry)) for i in xrange(header.NumberOfEntries)]

            o = dw.add_stream_placeholder(s.kind, s.fp.size)

            for e in entries:
                e.ModuleNameRva = dw.write_oob(make_str(load_str(e.ModuleNameRva))).RVA

            dw.set_stream(o, header.pack() + ''.join(e.pack() for e in entries))
            continue

        if s.kind == SystemInfoStream:
            si = MINIDUMP_SYSTEM_INFO.unpack_all(s.fp.read())
            si.CSDVersionRva = dw.write_oob(make_str(load_str(si.CSDVersionRva))).RVA
            dw.add_stream(s.kind, si.pack())
            continue

        if s.kind == ThreadListStream:
            NumberOfThreads, = read_struct(s.fp, '<I')
            thrs = MINIDUMP_THREAD.read(s.fp, 4, NumberOfThreads)
            o = dw.add_stream_placeholder(s.kind, 4 + MINIDUMP_THREAD.size * len(thrs))

            for thr in thrs:
                thr.Stack.Memory = dw.write_oob(load(thr.Stack.Memory))
                thr.ThreadContext = dw.write_oob(load(thr.ThreadContext))

            dw.set_stream(o, struct.pack('<I', len(thrs)) + ''.join(thr.pack() for thr in thrs))
            continue

        if s.kind == ModuleListStream:
            NumberOfModules, = read_struct(s.fp, '<I')
            mods = MINIDUMP_MODULE.read(s.fp, 4, NumberOfModules)
            o = dw.add_stream_placeholder(s.kind, 4 + MINIDUMP_MODULE.size * len(mods))

            for mod in mods:
                mod.CvRecord = dw.write_oob(load(mod.CvRecord))
                mod.MiscRecord = dw.write_oob(load(mod.MiscRecord))
                name = load_str(mod.ModuleNameRva)
                mod.ModuleNameRva = dw.write_oob(make_str(name)).RVA

            dw.set_stream(o, struct.pack('<I', len(mods)) + ''.join(mod.pack() for mod in mods))
            continue

        if s.kind == MemoryListStream:
            mls = s
            continue

        dw.add_stream(s.kind, s.fp)

    if mls:
        NumberOfMemoryRanges, = read_struct(mls.fp, '<I')
        descs = MINIDUMP_MEMORY_DESCRIPTOR.read(mls.fp, 4, NumberOfMemoryRanges)

        new_size = MINIDUMP_MEMORY_DESCRIPTOR64.size * len(descs) + MINIDUMP_MEMORY64_LIST.size
        o = dw.add_stream_placeholder(Memory64ListStream, new_size)

        descs.sort(key=lambda d: d.StartOfMemoryRange)
        #new_descs = [MINIDUMP_MEMORY_DESCRIPTOR64(desc.StartOfMemoryRange, desc.Memory.DataSize) for desc in descs]

        new_descs = []
        fout.seek(dw.current_size())
        for desc in descs:
            fin.seek(desc.Memory.RVA)
            buf = fin.read(desc.Memory.DataSize)
            fout.write(buf)

            if not new_descs or new_descs[-1].StartOfMemoryRange + new_descs[-1].DataSize != desc.StartOfMemoryRange:
                new_descs.append(MINIDUMP_MEMORY_DESCRIPTOR64(desc.StartOfMemoryRange, desc.Memory.DataSize))
            else:
                new_descs[-1].DataSize += desc.Memory.DataSize

        header = MINIDUMP_MEMORY64_LIST(len(new_descs), dw.current_size())
        dw.set_stream(o, header.pack() + ''.join(desc.pack() for desc in new_descs))

    if 0:
        NumberOfMemoryRanges, = read_struct(mls.fp, '<I')
        descs = MINIDUMP_MEMORY_DESCRIPTOR.read(mls.fp, 4, NumberOfMemoryRanges)
        descs.sort(key=lambda d: d.StartOfMemoryRange)

        stream_size = 4 + MINIDUMP_MEMORY_DESCRIPTOR.size * len(descs)
        o = dw.add_stream_placeholder(MemoryListStream, stream_size)

        p = dw.current_size()
        new_descs = []
        for desc in descs:
            new_descs.append(MINIDUMP_MEMORY_DESCRIPTOR(desc.StartOfMemoryRange,
                MINIDUMP_LOCATION_DESCRIPTOR(desc.Memory.DataSize, p)))
            p += desc.Memory.DataSize

        stream_content = struct.pack('<I', len(new_descs))
        stream_content += ''.join(desc.pack() for desc in new_descs)
        dw.set_stream(o, stream_content)

        fout.seek(dw.current_size())
        for desc in descs:
            fin.seek(desc.Memory.RVA)
            buf = fin.read(desc.Memory.DataSize)
            fout.write(buf)

    if mls64:
        header = MINIDUMP_MEMORY64_LIST.read(mls64.fp, 0)
        entries = [MINIDUMP_MEMORY_DESCRIPTOR64.read(mls64.fp) for i in xrange(header.NumberOfMemoryRanges)]

        o = dw.add_stream_placeholder(Memory64ListStream, mls64.fp.size)
        fin.seek(header.BaseRva)
        header.BaseRva = dw.current_size()
        dw.set_stream(o, header.pack() + ''.join(e.pack() for e in entries))

        fout.seek(dw.current_size())
        for e in entries:
            buf = fin.read(e.DataSize)
            fout.write(buf)

    dw.close()

def _main():
    parser = argparse.ArgumentParser()
    parser.add_argument('input', type=argparse.FileType('rb'))
    parser.add_argument('-o', '--output', type=argparse.FileType('wb'))
    args = parser.parse_args()

    if args.output is None:
        path, ext = os.path.splitext(args.input.name)
        if ext != '.dmp':
            ext += '.dmp'
        new_fname = path + '-full' + ext
        args.output = open(new_fname, 'wb')

    fulldumpize(args.input, args.output)
    return 0

if __name__ == '__main__':
    sys.exit(_main())
