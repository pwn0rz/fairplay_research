from typing import List, Tuple
from lldb import *
import shlex
import lldb

def get_nzcv(frame : SBFrame) -> Tuple[int,int,int,int]:
    cpsr : SBValue = frame.FindRegister('cpsr')
    error : SBError = SBError()
    cpsr_val = cpsr.GetValueAsUnsigned(error)
    assert error.Success()

    NZCV = (cpsr_val & 0xf0000000) >> 28

    return ((NZCV & 0x8) >> 3,(NZCV & 0x4) >> 2, (NZCV & 0x2) >> 1, NZCV & 0x1)

def get_conditions(frame : SBFrame) -> List[str]:
    conds = []
    (N,Z,C,V) = get_nzcv(frame)
    if Z == 1:
        conds.append('eq')
    if Z == 0:
        conds.append('ne')
    if C == 0:
        conds.append('cc')
    if C == 1:
        conds.append('cs')
    if C == 1 and Z == 0:
        conds.append('hi')
    if C == 0 and Z == 1:
        conds.append('ls')
    if N == V:
        conds.append('ge')
    if N != V:
        conds.append('lt')
    if Z == 0 and N == V:
        conds.append('gt')
    if Z == 1 and N != V:
        conds.append('le')
    
    return conds

def dump_conds(debugger : SBDebugger,  comamnd : str, result : SBCommandReturnObject, internal_dict):
    target : SBTarget = debugger.GetSelectedTarget()
    if target == None:
        result.SetError("no target selected")
        return
    process : SBProcess =  target.GetProcess()
    if process == None:
        result.SetError("no process being debugged")
        return

    state = process.GetState()
    if state != eStateStopped:
        result.SetError("process not stopped")
        return

    thread : SBThread = process.GetSelectedThread()
    frame : SBFrame = thread.GetFrameAtIndex(0)

    conds = get_conditions(frame)
    (N,Z,C,V) = get_nzcv(frame)
    result.AppendMessage(f'[*] NZCV: {N} {Z} {C} {V}')
    result.AppendMessage(f'[*] conditions: {" ".join(conds)}')

def step_to_branch(debugger : SBDebugger,  comamnd : str, result : SBCommandReturnObject, internal_dict):
    error : SBError = SBError()

    target : SBTarget = debugger.GetSelectedTarget()
    if target == None:
        result.SetError("no target selected")
        return
    process : SBProcess =  target.GetProcess()
    if process == None:
        result.SetError("no process being debugged")
        return

    state = process.GetState()
    if state != eStateStopped:
        result.SetError("process not stopped")
        return

    thread : SBThread = process.GetSelectedThread()
    
    instr : SBInstruction = None
    thread.StepInstruction(True)
    while True:
        frame : SBFrame = thread.GetSelectedFrame()
        pos = frame.GetPCAddress().GetLoadAddress(target)

        content = process.ReadMemory(pos,4,error)
        if not error.Success():
            result.AppendWarning(f'failed to read instruction at {pos}: {error}')
            break

        instr = target.GetInstructions(SBAddress(pos,target),content)[0]
        mnem = instr.GetMnemonic(target).lower()
        if not instr.is_branch:
            thread.StepInstruction(True)
            if mnem == 'cmp' or mnem == 'tst':
                (N,Z,C,V) = get_nzcv(frame)
                result.AppendMessage('[*] hit cmp/hit instruction:')
                result.AppendMessage(f'\t{instr}')
                result.AppendMessage(f'\tNZCV: {N} {Z} {C} {V}')
                conds = get_conditions(frame)
                result.AppendMessage(f'\tcondtions: {" ".join(conds)}')
        else:
            break
    
    mnem : str = instr.GetMnemonic(target).lower()
    result.AppendMessage("[*] hit branch instruction")
    if 'br' in mnem or 'blr' in mnem:
        # br / braa / blr / blraa 
        ops : str = instr.GetOperands(target)
        value : SBValue = frame.FindRegister(ops.split(',')[0].rstrip())
        branch_target = value.GetValueAsAddress()
        content = process.ReadMemory(branch_target,4,error)
        assert error.Success()

        target_instr = target.GetInstructions(SBAddress(branch_target,target),content)[0]
        symbol = target_instr.GetAddress().GetSymbol()
        result.AppendMessage(f'\tsource: {instr}\n\ttarget: {target_instr}\n\tsymbol: {symbol.GetName()}\n')
        result.flush()
    elif 'b.' in mnem:
        # b.cond / bl
        ops : str = instr.GetOperands(target)
        branch_taken : SBAddress = SBAddress(int(ops,0),target)
        branch_not_taken : SBAddress = SBAddress(instr.GetAddress().GetLoadAddress(target) + 4,target)
        branch_target : int = None

        cond = mnem.split('.')[1]
        conds = get_conditions(frame)
        if cond in conds:
            branch_target = branch_taken.GetLoadAddress(target)
        else:
            branch_target = branch_not_taken.GetLoadAddress(target)

        content = process.ReadMemory(branch_target,4,error)
        assert error.Success()

        target_instr = target.GetInstructions(SBAddress(branch_target,target),content)[0]
        symbol = target_instr.GetAddress().GetSymbol()
        result.AppendMessage(f'\tsource: {instr}\n\ttarget: {target_instr}\n\tsymbol: {symbol.GetName()}\n')
        result.flush()


    debugger.HandleCommand('process status')

def __lldb_init_module(debugger : SBDebugger, internal_dict):
    debugger.HandleCommand('command script add -f branch.dump_conds conds')
    debugger.HandleCommand('command script add -f branch.step_to_branch sb')
