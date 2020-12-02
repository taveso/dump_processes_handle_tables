
'''
    !load pykd
    !pykd.py C:\pykd\dump_processes_handle_tables.py
    !unload pykd
'''

from pykd import *

nt = module("nt")

g_pid = ''
g_pid_to_process = {}

g_processes_whitelist = set([
    'MsMpEng.exe',
    'NisSrv.exe'
])

g_object_type_names = set([
    'ALPC Port',
    'Desktop',
    'Directory',
    'DmaDomain',
    'EtwConsumer',
    'EtwRegistration',
    'Event',
    'File',
    'FilterCommunicationPort',
    'FilterConnectionPort',
    'IRTimer',
    'IoCompletion',
    'Key',
    'Mutant',
    'Partition',
    'PcwObject',
    'Process',
    'RawInputManager',
    'Section',
    'Semaphore',
    'Session',
    'SymbolicLink',
    'Thread',
    'Timer',
    'TmRm',
    'TmTm',
    'Token',
    'TpWorkerFactory',
    'WaitCompletionPacket',
    'WindowStation'
])

g_object_name_to_object_type = {}

g_object_name_to_pids = {}

def get_object_name(object_header, object_header_addr):    
    object_header_name_info_addr = object_header_addr - loadBytes(nt.ObpInfoMaskToOffset + (object_header.InfoMask & 0x3), 1)[0]

    object_header_name_info = nt.typedVar("_OBJECT_HEADER_NAME_INFO", object_header_name_info_addr)

    Name = object_header_name_info.Name

    object_name = loadUnicodeString(Name)

    return object_name

'''
    kd> u nt!ObGetObjectType
    nt!ObGetObjectType:
    fffff801`e16ca53c 488d41d0        lea     rax,[rcx-30h]
    fffff801`e16ca540 0fb649e8        movzx   ecx,byte ptr [rcx-18h]
    fffff801`e16ca544 48c1e808        shr     rax,8
    fffff801`e16ca548 0fb6c0          movzx   eax,al
    fffff801`e16ca54b 4833c1          xor     rax,rcx
    fffff801`e16ca54e 0fb60d0b3feeff  movzx   ecx,byte ptr [nt!ObHeaderCookie (fffff801`e15ae460)]
    fffff801`e16ca555 4833c1          xor     rax,rcx
    fffff801`e16ca558 488d0dd143eeff  lea     rcx,[nt!ObTypeIndexTable (fffff801`e15ae930)]

    kd> dd nt!ObHeaderCookie L1
    fffff801`e15ae460  d1370655

    kd> dd nt!ObTypeIndexTable L79
    fffff801`e15ae930  00000000 00000000 d39b4000 ffff8300
    fffff801`e15ae940  cd027c40 ffff9c04 cd022490 ffff9c04
    fffff801`e15ae950  cd0af610 ffff9c04 cd0235c0 ffff9c04
    fffff801`e15ae960  cd0b4290 ffff9c04 cd028410 ffff9c04
    fffff801`e15ae970  cd01f620 ffff9c04 cd023f20 ffff9c04
    fffff801`e15ae980  cd0aa080 ffff9c04 cd0aa3d0 ffff9c04
    fffff801`e15ae990  cd0aa270 ffff9c04 cd0aac60 ffff9c04
    fffff801`e15ae9a0  cd093430 ffff9c04 cd0932d0 ffff9c04
    fffff801`e15ae9b0  cd0abed0 ffff9c04 cd0b0f20 ffff9c04
    fffff801`e15ae9c0  cd0b0dc0 ffff9c04 cd0b0c60 ffff9c04
    fffff801`e15ae9d0  cd0b16c0 ffff9c04 cd0b1560 ffff9c04
    fffff801`e15ae9e0  cd0b1400 ffff9c04 cd10c660 ffff9c04
    fffff801`e15ae9f0  cd10c500 ffff9c04 cd10c3a0 ffff9c04
    fffff801`e15aea00  cd10c240 ffff9c04 cd148f20 ffff9c04
    fffff801`e15aea10  cd148dc0 ffff9c04 cd148c60 ffff9c04
    fffff801`e15aea20  cd148b00 ffff9c04 cd1489a0 ffff9c04
    fffff801`e15aea30  cd149f20 ffff9c04 cd149dc0 ffff9c04
    fffff801`e15aea40  cd149c60 ffff9c04 cd149b00 ffff9c04
    fffff801`e15aea50  cd1499a0 ffff9c04 cd147f20 ffff9c04
    fffff801`e15aea60  cd147dc0 ffff9c04 cd147ad0 ffff9c04
    fffff801`e15aea70  cd147970 ffff9c04 cd146f20 ffff9c04
    fffff801`e15aea80  cd13bf20 ffff9c04 cd13bdc0 ffff9c04
    fffff801`e15aea90  cd13aa20 ffff9c04 cd1388e0 ffff9c04
    fffff801`e15aeaa0  cd1de570 ffff9c04 cd1da3b0 ffff9c04
    fffff801`e15aeab0  cd1d8080 ffff9c04 cd0b93e0 ffff9c04
    fffff801`e15aeac0  cd0c5dd0 ffff9c04 cdfefae0 ffff9c04
    fffff801`e15aead0  ce548870 ffff9c04 ce548710 ffff9c04
    fffff801`e15aeae0  ce531570 ffff9c04 cd3ae9f0 ffff9c04
    fffff801`e15aeaf0  cd3ae890 ffff9c04 cd3aff20 ffff9c04
    fffff801`e15aeb00  ceae0670 ffff9c04 cd022f20 ffff9c04
    fffff801`e15aeb10  00000000
    kd> ? 0x79-0x3
    Evaluate expression: 118 = 00000000`00000076
'''
def get_object_type_index(object_header, object_header_addr):    
    object_type_index = ((object_header_addr >> 8) ^ object_header.TypeIndex ^ loadBytes(nt.ObHeaderCookie, 1)[0]) & 0xFF

    assert(object_type_index < 118)

    return object_type_index

def dump_process_handle_table_level0(table_base, handle_cnt):
    global g_object_type_names
    global g_object_name_to_object_type
    global g_pid
    global g_object_name_to_pids

    i = 0
    while (i < 256) and (handle_cnt > 0):
        dprintln('dump_process_handle_table_level0() i: %d' % i)

        handle_table_entry = ptrPtr(table_base + i * 0x10)

        if handle_table_entry == 0:
            i = i + 1
            continue

        #
        #   object header
        #

        object_header_addr = ((handle_table_entry >> 16) | 0xFFFF000000000000) & 0xFFFFFFFFFFFFFFF0

        object_header = nt.typedVar("_OBJECT_HEADER", object_header_addr)

        #
        #   object type
        #

        object_type_index = get_object_type_index(object_header, object_header_addr)

        object_type_addr = ptrPtr(nt.ObTypeIndexTable + object_type_index * 0x8)

        object_type = nt.typedVar("_OBJECT_TYPE", object_type_addr)

        object_type_name = loadUnicodeString(object_type.Name)
        # dprintln('object_type_name: %s' % object_type_name)
        # assert(object_type_name in g_object_type_names)

        #
        #   object name
        #

        InfoMask = object_header.InfoMask

        # name information subheader
        if (InfoMask & 0x2) != 0:
            object_name = get_object_name(object_header, object_header_addr)
        else:
            object_name = ''

        #
        #   object name to object type
        #   object name to pids
        #

        g_object_name_to_object_type[object_name] = object_type_name

        if object_name not in g_object_name_to_pids:
            g_object_name_to_pids[object_name] = set([])

        g_object_name_to_pids[object_name].add(g_pid)

        handle_cnt = handle_cnt - 1
        i = i + 1

    return handle_cnt

def dump_process_handle_table_level1(table_base, handle_cnt):
    for i in range(0, 512):
        dprintln('dump_process_handle_table_level1() i: %d' % i)
        
        table_level0 = ptrPtr(table_base + i * 0x8)
        assert(table_level0 != 0)

        handle_cnt = dump_process_handle_table_level0(table_level0, handle_cnt)

        if (handle_cnt == 0):
            break

    assert(handle_cnt == 0)

def dump_processes_handle_tables():
    global g_pid
    global g_pid_to_process
    global g_processes_whitelist

    processes = typedVarList(nt.PsActiveProcessHead, "nt!_EPROCESS", "ActiveProcessLinks")

    for process in processes:

        #
        #   process id to process image filename
        #
        
        UniqueProcessId = process.UniqueProcessId

        ImageFileName = ''.join([chr(c) for c in process.ImageFileName if c != 0]) # remove null bytes

        if ImageFileName not in g_processes_whitelist:
            continue

        g_pid = hex(UniqueProcessId)

        g_pid_to_process[g_pid] = ImageFileName

        #
        #   process handle table
        #
        
        if process.ObjectTable == 0:
            continue

        handle_table = nt.typedVar("_HANDLE_TABLE", process.ObjectTable)

        TableCode = handle_table.TableCode

        table_level = TableCode & 0x3
        assert((table_level == 0) or (table_level == 1))

        table_base = TableCode & ~0x3

        FreeLists = nt.typedVar("_HANDLE_TABLE_FREE_LIST", handle_table.FreeLists)

        handle_cnt = FreeLists.HandleCount

        #
        #   dump process handle table
        #

        dprintln('Process %s "%s"' % (g_pid, g_pid_to_process[g_pid]))
        dprintln('handles %d table_level %d' % (handle_cnt, table_level))

        if table_level == 0:
            handle_cnt = dump_process_handle_table_level0(table_base, handle_cnt)
            assert(handle_cnt == 0)

        elif table_level == 1:
            dump_process_handle_table_level1(table_base, handle_cnt)

def main():
    global g_object_name_to_object_type
    global g_object_name_to_pids
    global g_pid_to_process
    
    if not isKernelDebugging():
        dprintln("This script is for x64 kernel debugging only")
        return

    dump_processes_handle_tables()

    for object_name in sorted(g_object_name_to_pids):
        if object_name:
            if len(g_object_name_to_pids[object_name]) > 1:
                dprintln("[+] OBJECT_TYPE %s, OBJECT_NAME \"%s\"" % (g_object_name_to_object_type[object_name], object_name))

                for pid in g_object_name_to_pids[object_name]:
                    dprintln('\tPID %s: "%s"' % (int(pid, 16), g_pid_to_process[pid]))

if __name__ == "__main__":
    main()
