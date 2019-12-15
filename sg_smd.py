import os
import struct
import idaapi
import ida_funcs
import ida_bytes

"""
This is a IDA loader for SEGA Megadrive/Genesis ROM's

To use this script, drop it in your IDA loaders directory
"""

__author__    = 'zznop'
__copyright__ = 'Copyright 2019, zznop'
__email__     = 'zznop0x90@gmail.com'

def get_dword_at(li, offset):
    """
    Get dword at specified offset

    :param li: Loader input
    :param offset: Offset
    """

    li.seek(offset)
    return struct.unpack('>I', li.read(4))[0]

def create_word_and_name(offset, name):
    """
    Apply word type to offset and name it

    :param offset: Offset of word
    :param name: Name to apply
    """

    idaapi.create_word(offset, 2)
    idaapi.set_name(offset, name, idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)

def create_dword_and_name(offset, name):
    """
    Apply dword type to offset and name it

    :param offset: Offset of word
    :param name: Name to apply
    """

    idaapi.create_dword(offset, 4)
    idaapi.set_name(offset, name, idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)

def create_interrupt_table():
    """
    Create interrupt vector table
    """

    create_dword_and_name(8, 'VectOffBusError')
    create_dword_and_name(12, 'VectOffAddressError')
    create_dword_and_name(16, 'VectOffIllegalInstruction')
    create_dword_and_name(20, 'VectOffDivisionByZero')
    create_dword_and_name(24, 'VectOffChkException')
    create_dword_and_name(28, 'VectOffTrapVException')
    create_dword_and_name(32, 'VectOffPrivilegeViolation')
    create_dword_and_name(36, 'VectOffTraceException')
    create_dword_and_name(40, 'VectOffLineAEmulator')
    create_dword_and_name(44, 'VectOffLineFEmulator')
    create_dword_and_name(48, 'VectUnused00')
    create_dword_and_name(52, 'VectUnused01')
    create_dword_and_name(56, 'VectUnused02')
    create_dword_and_name(60, 'VectUnused03')
    create_dword_and_name(64, 'VectUnused04')
    create_dword_and_name(68, 'VectUnused05')
    create_dword_and_name(72, 'VectUnused06')
    create_dword_and_name(76, 'VectUnused07')
    create_dword_and_name(80, 'VectUnused08')
    create_dword_and_name(84, 'VectUnused09')
    create_dword_and_name(88, 'VectUnused10')
    create_dword_and_name(92, 'VectUnused11')
    create_dword_and_name(96, 'VectOffSpuriousException')
    create_dword_and_name(100, 'VectOffIrqL1')
    create_dword_and_name(104, 'VectOffIrqL2')
    create_dword_and_name(108, 'VectOffIrqL3')
    create_dword_and_name(112, 'VectOffIrqL4')
    create_dword_and_name(116, 'VectOffIrqL5')
    create_dword_and_name(120, 'VectOffIrqL6')
    create_dword_and_name(124, 'VectOffIrqL7')
    create_dword_and_name(128, 'VectOffTrap00')
    create_dword_and_name(132, 'VectOffTrap01')
    create_dword_and_name(136, 'VectOffTrap02')
    create_dword_and_name(140, 'VectOffTrap03')
    create_dword_and_name(144, 'VectOffTrap04')
    create_dword_and_name(148, 'VectOffTrap05')
    create_dword_and_name(152, 'VectOffTrap06')
    create_dword_and_name(156, 'VectOffTrap07')
    create_dword_and_name(160, 'VectOffTrap08')
    create_dword_and_name(164, 'VectOffTrap09')
    create_dword_and_name(168, 'VectOffTrap10')
    create_dword_and_name(172, 'VectOffTrap11')
    create_dword_and_name(176, 'VectOffTrap12')
    create_dword_and_name(180, 'VectOffTrap13')
    create_dword_and_name(184, 'VectOffTrap14')
    create_dword_and_name(188, 'VectOffTrap15')
    create_dword_and_name(192, 'VectUnused12')
    create_dword_and_name(196, 'VectUnused13')
    create_dword_and_name(200, 'VectUnused14')
    create_dword_and_name(204, 'VectUnused15')
    create_dword_and_name(208, 'VectUnused16')
    create_dword_and_name(212, 'VectUnused17')
    create_dword_and_name(216, 'VectUnused18')
    create_dword_and_name(220, 'VectUnused19')
    create_dword_and_name(224, 'VectUnused20')
    create_dword_and_name(228, 'VectUnused21')
    create_dword_and_name(232, 'VectUnused22')
    create_dword_and_name(236, 'VectUnused23')
    create_dword_and_name(240, 'VectUnused24')
    create_dword_and_name(244, 'VectUnused25')
    create_dword_and_name(248, 'VectUnused26')
    create_dword_and_name(252, 'VectUnused27')

def create_interrupt_handlers(li):
    """
    Make code at interrupt handler callbacks

    :param li: Loader input
    """

    li.seek(8)
    for _ in range(8, 256, 4):
        dword = struct.unpack('>I', li.read(4))[0]
        ida_funcs.add_func(dword)

def create_rom_info_block():
    """
    Create ROM information block
    """

    idaapi.set_name(256, 'ConsoleName', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    ida_bytes.create_strlit(256, 16, 0)
    idaapi.set_name(272, 'Copyright', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    ida_bytes.create_strlit(272, 16, 0)
    idaapi.set_name(288, 'DomesticName', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    ida_bytes.create_strlit(288, 48, 0)
    idaapi.set_name(336, 'InternationalName', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    ida_bytes.create_strlit(336, 48, 0)
    idaapi.set_name(384, 'SerialRevision', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    ida_bytes.create_strlit(384, 14, 0)
    create_word_and_name(398, 'Checksum')
    idaapi.set_name(400, 'IoSupport', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    ida_bytes.create_strlit(400, 16, 0) # TODO create byte array
    create_dword_and_name(416, 'RomStart')
    create_dword_and_name(420, 'RomEnd')
    create_dword_and_name(424, 'RamStart')
    create_dword_and_name(428, 'RamEnd')
    idaapi.set_name(432, 'SramInfo', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    ida_bytes.create_strlit(432, 12, 0)
    idaapi.set_name(444, 'Notes', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    ida_bytes.create_strlit(444, 52, 0)
    idaapi.set_name(496, 'Region', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    ida_bytes.create_strlit(496, 16, 0)

def label_z80_memory():
    """
    Apply names and create types for important Z80 offsets
    """

    idaapi.set_name(0xa10000, 'Z80VersionReg', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    idaapi.set_name(0xa10002, 'Ctrl1Data', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    idaapi.set_name(0xa10004, 'Ctrl2Data', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    idaapi.set_name(0xa10006, 'ExpPortData', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    idaapi.set_name(0xa10008, 'Ctrl1Ctrl', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    idaapi.set_name(0xa1000a, 'Ctrl2Ctrl', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    idaapi.set_name(0xa1000c, 'ExpPortCtrl', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    idaapi.set_name(0xa1000e, 'Ctrl1SerTx', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    idaapi.set_name(0xa10010, 'Ctrl1SerRx', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    idaapi.set_name(0xa10012, 'Ctrl1SerCtrl', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    idaapi.set_name(0xa10014, 'Ctrl2SerTx', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    idaapi.set_name(0xa10016, 'Ctrl2SerRx', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    idaapi.set_name(0xa10018, 'Ctrl2SerCtrl', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    idaapi.set_name(0xa1001a, 'ExpPortSerTx', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    idaapi.set_name(0xa1001c, 'ExpPortSerRx', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    idaapi.set_name(0xa1001e, 'ExpPortSerCtrl', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    idaapi.set_name(0xa11000, 'MemoryModeReg', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    idaapi.set_name(0xa11100, 'Z80BusRequest', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    idaapi.set_name(0xa11201, 'Z80Reset', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    idaapi.set_name(0xa13000, 'TIMERegs', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    create_word_and_name(0xa130f1, 'SRAMAccessReg')
    create_word_and_name(0xa130f3, 'BankReg_80000_fffff')
    create_word_and_name(0xa130f5, 'BankReg_100000_17ffff')
    create_word_and_name(0xa130f7, 'BankReg_180000_1fffff')
    create_word_and_name(0xa130f9, 'BankReg_200000_27ffff')
    create_word_and_name(0xa130fb, 'BankReg_280000_2fffff')
    create_word_and_name(0xa130fd, 'BankReg_300000_37ffff')
    create_word_and_name(0xa130ff, 'BankReg_380000_3fffff')
    idaapi.set_name(0xa14000, 'TMSS_SEGA', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    idaapi.set_name(0xa14101, 'TMSS_CartReg', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)

def label_misc_regs_ports():
    """
    Label random ports and regs from 0xC00000-0xC00020
    """

    create_word_and_name(0xC00000, 'VDPData')
    create_word_and_name(0xC00002, 'VDPDataMirror')
    create_word_and_name(0xC00004, 'VDPCtrl')
    create_word_and_name(0xC00006, 'VDPCtrlMirror')
    create_word_and_name(0xC00008, 'VDPHVCounter')
    create_word_and_name(0xC0000A, 'VDPHVCounterMirror')
    create_word_and_name(0xC00011, 'PSGOutput')
    create_word_and_name(0xC00013, 'PSGOutputMirror')
    create_word_and_name(0xC0001c, 'DebugReg')
    create_word_and_name(0xC0001e, 'DebugRegMirror')


def accept_file(li, filename):
    """
    Determine if the input file is a valid SG/SMD ROM

    :param li: Loader input
    :param filename: Name of file
    :return: Dictionary containing file information if loadable, otherwise 0
    """

    # Large enough to contain vector table and ROM info?
    if li.size() < 0x1f4:
        return 0

    # Read in console name and ensure it contains SEGA
    li.seek(0x100)
    console_name = li.read(16).decode('utf-8')
    if 'SEGA' not in console_name.upper():
        return 0

    # Ensure ROM starts at 0
    li.seek(0x1a0)
    rom_start = struct.unpack('>I', li.read(4))[0]
    if rom_start != 0:
        return 0

    # Ensure RAM starts at 0xff0000
    li.seek(0x1a8)
    ram_start = struct.unpack('>I', li.read(4))[0]
    if ram_start != 0xff0000:
        return 0

    return {
        'format': 'SMD/SG ROM',
        'processor': '68000',
        'options': 1|idaapi.ACCEPT_FIRST
    }

def load_file(li, neflags, format):
    """
    Load the SG/SMD ROM

    :param li: Loader input
    :param neflags:
    :param format:
    :return: 1 on success, otherwise 0
    """

    idaapi.set_processor_type('68000', idaapi.SETPROC_LOADER)
    is_reload = (neflags & idaapi.NEF_RELOAD) != 0
    if is_reload:
        return 1

    # Get ROM end
    li.seek(0x1a4)
    rom_end = struct.unpack('>I', li.read(4))[0]

    # Create ROM segment
    rom_seg = idaapi.segment_t()
    rom_seg.start_ea = 0
    rom_seg.end_ea = rom_end
    rom_seg.bitness = 1
    idaapi.add_segm_ex(rom_seg, 'ROM', 'CODE', idaapi.ADDSEG_OR_DIE)

    # Get RAM start/end
    li.seek(0x1a8)
    ram_start = struct.unpack('>I', li.read(4))[0]
    ram_end = struct.unpack('>I', li.read(4))[0]

    # Create RAM segment
    ram_seg = idaapi.segment_t()
    ram_seg.start_ea = ram_start
    ram_seg.end_ea = ram_end
    ram_seg.bitness = 1
    idaapi.add_segm_ex(ram_seg, 'RAM', 'DATA', idaapi.ADDSEG_OR_DIE)

    # Read file into ROM segment
    li.seek(0)
    li.file2base(0, 0, rom_end, False)

    # Create Z80 memory segment
    z80_seg = idaapi.segment_t()
    z80_seg.start_ea = 0xa00000
    z80_seg.end_ea = 0xa1ffff # Actually ends at 0xa0ffff, but for the sake of applying labels we make it 0xa1ffff
    z80_seg.bitness = 0 # 16 bit
    idaapi.add_segm_ex(z80_seg, 'Z80', 'DATA', idaapi.ADDSEG_OR_DIE)
    label_z80_memory()

    # Create a segment so we can create labels for VDP ports and debug registers
    misc_ports_regs = idaapi.segment_t()
    misc_ports_regs.start_ea = 0xc00000
    misc_ports_regs.end_ea = 0xc00020
    misc_ports_regs.bitness = 1
    idaapi.add_segm_ex(misc_ports_regs, 'MISC', 'DATA', idaapi.ADDSEG_OR_DIE)
    label_misc_regs_ports()

    # Create interrupt vector table
    create_dword_and_name(0, 'StackOffset')
    create_dword_and_name(4, 'ProgramStart')
    create_interrupt_table()
    create_interrupt_handlers(li)

    # Create ROM info
    create_rom_info_block()

    # Set entry
    program_start = get_dword_at(li, 4)
    idaapi.add_entry(program_start, program_start, '_start', 1)
    return 1
