#!/usr/bin/env pyhthon2
import idc
from syscall_def import *

DEBUG_PRINTS = False

# Converts IDA Pro number strings to int
def get_int_from_ida_num_str(num_str):
    # Convert syscall number string to int
    if 'h' in num_str:
        num_str = num_str.replace('h', '')
        return int(num_str, 16)
    return int(num_str)

# Check first instruction (mov rax, XX)
# Returns the syscall number if successful
# None if not
def check_first_instruction(inst):
    if idc.GetMnem(inst) != 'mov':
        return
    if idc.GetOpnd(inst, 0) == 'rax':
        return idc.GetOpnd(inst, 1)

# Check second instruction (mov r10, rcx)
# Returns True if the instruction matches
# Otherwise False
def check_second_instruction(inst):
    mnem = idc.GetMnem(inst)
    if mnem != 'mov':
        return False
    if idc.GetOpnd(inst, 0) == 'r10' or idc.GetOpnd(inst, 1) == 'rcx':
        return True
    return False

# Returns true if the instruction is a syscall
def check_third_instruction(inst):
    mnem = idc.GetMnem(inst)
    if mnem == 'syscall':
        return True
    return False

# Checks if the function is a syscall wrapper
# If it is, return the string to rename the function to
# Otherwise, return None
def get_function_name(function_ea):
    syscall_num_str = 'unknown_syscall_num'

    # Get the first chunk
    startea, endea = Chunks(function_ea).next()

    # Get the first 3 instructions
    heads = Heads(startea, endea)
    try:
        inst1 = heads.next()
        inst2 = heads.next()
        inst3 = heads.next()
    except StopIteration:
        return

    # Check first instruction
    syscall_num_str = check_first_instruction(inst1)
    if syscall_num_str == None:
        return

    # Check second instruction
    if not check_second_instruction(inst2):
        return

    # Check third instruction (syscall)
    if not check_third_instruction(inst3):
        return

    # Convert the syscall_num_str to an int
    if DEBUG_PRINTS:
        print('syscall detected: %s' % syscall_num_str)
    syscall_num = get_int_from_ida_num_str(syscall_num_str)

    # Resolve syscall name
    if syscall_num > sce_max_syscall_num:
        print('New Syscall: %d' % syscall_num)
    if syscall_num in syscall_table:
        return syscall_table[syscall_num]
    elif syscall_num <= freebsd_max_syscall_num:
        return '%s%d' % (freebsd_generic, syscall_num)
    else:
        return '%s%d' % (sce_generic, syscall_num)


# Walks through every function, renaming
# the syscall wrappers as they are encountered
def walk_functions():
    func_names = []
    ea = idc.ScreenEA()

    for function_ea in Functions(idc.SegStart(ea), idc.SegEnd(ea)):
        # Get the old function name for debug purposes
        if DEBUG_PRINTS:
            func_name = idc.GetFunctionName(function_ea)
            print hex(function_ea), func_name

        new_func_name = get_function_name(function_ea)
        if new_func_name != None:
            while new_func_name in func_names:
                print('Duplicate Function Name: %s' % new_func_name)
                new_func_name = new_func_name + '_duplicate'
            func_names.append(new_func_name)
            idc.MakeName(function_ea, new_func_name)

walk_functions()
