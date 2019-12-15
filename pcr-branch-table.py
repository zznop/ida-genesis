import ida_segment
import ida_bytes
import idautils
import idaapi
import idc
import re

"""
IDA script that identifies and invokes analysis on a specific branch table
pattern that isn't picked up by auto-analysis.

Example:

0xd50    jsr $10(pc, d0.w)
...
0xd60    rte
0xd62    bra ($00000db6) # Sometimes auto-analysis will fail ...
0xd66    bra ($00004196) # to disassemble this table
"""

__author__     = 'zznop'
__copyright__  = 'Copyright 2019, zznop'
__email__      = 'zznop0x90@gmail.com'

def get_branch_table_instrs():
    """
    Return all jsr or jmp instructions with pc in the operand

    :return: List of PC-relative jmp and jsr dispatch instructions
    """

    instrs = []
    # Iterate instructions in functions
    for funcea in idautils.Functions():
        for (startea, endea) in idautils.Chunks(funcea):
            for head in idautils.Heads(startea, endea):
                instr = idc.GetDisasm(head).split()
                if instr[0] == 'jsr' or instr[0] == 'jmp':
                    if 'pc' in instr[1]:
                        instrs.append(instr)

    # Iterate instructions not in a function
    addr = idaapi.find_not_func(0, 1)
    while addr != idc.BADADDR:
        instr = idc.GetDisasm(addr).split()
        if instr[0] == 'jsr' or instr[0] == 'jmp':
            if 'pc' in instr[1]:
                instrs.append(instr)
        addr = idaapi.find_not_func(addr, 1)

    return instrs

def get_branch_table_base_from_instrs(instrs):
    """
    Get the base addr of the call tables from the pc-relative branch instructions

    :param instrs: jmp and jsr instructions that contain PC in the operand
    :return: List of branch table base addresses
    """

    branch_table_addrs = []
    for mnem, opnd in instrs:
        match = re.match(r"^.*_(.*)\(pc,.*\)$", opnd)
        if match:
            addr = int(match.group(1), 16)
            branch_table_addrs.append(addr)
            print(hex(addr))
    return branch_table_addrs

def disas_branch_tables(base_table_addrs):
    """
    Disassemble branches in table

    :param base_table_addrs: List of base addresses for branch tables
    """

    for base_addr in base_table_addrs:
        i = base_addr
        while True:
            instr_dword = ida_bytes.get_32bit(i)
            if not ((instr_dword >> 24) == 0x60):
                break
            ida_auto.auto_make_code(i)
            i += 4

def main():
    branch_table_instrs = get_branch_table_instrs()
    if branch_table_instrs is []:
        print('[+] No PC-relative jsr or jmp instructions found')
        return

    branch_table_addrs = get_branch_table_base_from_instrs(branch_table_instrs)
    if branch_table_addrs is []:
        print("[!] Failed to enumerate call table base addresses from instructions")
        return

    print('[+] Found {} branch tables'.format(len(branch_table_addrs)))
    disas_branch_tables(branch_table_addrs)

if __name__ == '__main__':
    main()
