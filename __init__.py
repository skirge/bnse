import angr
import string
import claripy
import archinfo
import tempfile
import sys
import pprint
import codecs
from binaryninja.highlight import HighlightColor
from binaryninja.enums import HighlightStandardColor, MessageBoxButtonSet, MessageBoxIcon
from binaryninja.plugin import PluginCommand, BackgroundTaskThread, BackgroundTask
import binaryninja.interaction as interaction
from binaryninja.interaction import get_save_filename_input, show_message_box
import binaryninja as binja
from binaryninja import log
from binaryninja import BinaryView, SectionSemantics
from abc import ABC, abstractmethod

import os
import json
import collections
import binascii
import struct

registers = {}
with open(os.path.dirname(__file__)+'/registers.json') as f:
  registers = json.load(f)

from string import ascii_uppercase, ascii_lowercase, digits

import os
os.environ['PWNLIB_NOTERM'] = 'True'
from pwnlib.util import cyclic

import logging
logging.getLogger('angr').setLevel('WARNING')

add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, \
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS, \
            angr.options.CONSTRAINT_TRACKING_IN_SOLVER }

#add_options = angr.options.modes['tracing']

def indent(level):
    return "  >"*level

def get_named_type(func):
    named_type = (str(func.type.return_value)
                  + ' '
                  + func.name
                  + '('
                  + (', '.join(map(str, func.type.parameters)))
                  + ')')
    return named_type

class MaxLengthException(Exception):
    pass

class WasNotFoundException(Exception):
    pass

def pattern_gen(length):
    return cyclic.cyclic(length)

def p32(data, endian="big"):
    if endian == "big":
       return struct.pack('>I', data)
    else:
        return struct.pack('<I', data)

def u32(data, endian="big"):
    if endian == "big":
        return hex(struct.unpack('>I', data)[0])
    else:
        return hex(struct.unpack('<I', data)[0])

def pattern_search(search_pattern):
    try:
        return cyclic.cyclic_find(search_pattern, len(search_pattern))
    except:
        return cyclic.cyclic_find(search_pattern)

class Explorer(ABC):
    """
    Abstract explorer class
    
    Methods
    -------
    run()
        Override by inherited class
    
    explorer
        Override by inherited class
    """

    @abstractmethod
    def run(self):
        pass

    @abstractmethod
    def explore(self):
        pass


class MainExplorer(Explorer):
    """
    Abstract MainExplorer class
    
    Methods
    -------
    feed_function_state()
        Override by inherited class, used to provide state for hooked function
    
    set_args()
        Override by inherited class, used to set angr arguments for function state
    
    set_sim_manager()
        Override by inhertied class, used to set simulation manager 
    """

    @abstractmethod
    def explore(self):
        pass

    @abstractmethod
    def feed_function_state(self):
        pass

    @abstractmethod
    def set_args(self):
        pass

    @abstractmethod
    def set_sim_manager(self):
        pass

    @abstractmethod
    def _get_endianess(self):
        pass

class UIPlugin(PluginCommand):
    """
    Abstract explorer class

    Attributes
    ----------
    path - used to keep traversed path by symbolic execution
    
    Methods
    -------

    choice_menu(self, bv)
        public, used to provide dropdown with shared libraries

    clear_start_address(self, bv)
        public, clear start address selection
    
    clear(self, bv)
        publuc, clear all UI information

    clear_end_address(self, bv)
        public, clear end address selection
    
    _clear_address(self, bv, addr)
        private, helper function to clear addresses
    
    color_path(self,bv, addr)
        public, set color for execution path
    
    _convert_menu_results(self, input_data, mapped_types, size)
        private, convert UI results to data that could be processed by Explorers
    
    display_message(self, title, desc)
        displays message box 
    
    dump_regs(self, state, registers, *include)
        public, dump and display information about registers
    
    __generate_menu_text_fields(self, arg_types)
        private, generate UI menu base on function params type

    _get_menu_results(self, menu_items, param_num)
        private, generate results dictionary
    
    __mapper(self, params)
        public, maps list of function params to types that BinaryNinja support
     
    _pattern_create(self, params)
        private, create pattern data for all fields for which user selected "pattern" option
    
    set_start_address(bv, addr)
        public, set start address for execution 

    set_end_address(bv, addr)
        public, set end address for execution 

    set_ld_path(self, bv)
        public, used to provide shared library path information

    _display_converted_params(self, params):
        private, used to provide console information for params

    set_function_params(self, bv, addr)
        public, display menu and convert all required params for Explorers
   
    """


    path = []

    def __init__(self):
        """
        Parameters
        ----------
        start : BinaryView address
            start address of execution
        end: BinaryView address
            end address of execution
        """

        self.start = None
        self.end = None

    def set_ld_path(self, bv):
        """
        Parameters
        ----------
        bv : BinaryView instance
        """

        path = interaction.get_directory_name_input("Select LD_PATH")
        if(not path):
            return
        binja.log_info("Selected LD_PATH: {0}".format(path))
        BackgroundTaskManager.ld_path = path.decode()

    def choice_menu(self, bv):
        """
        Parameters
        ----------
        bv : BinaryView instance
        """

        try:
            proj = angr.Project(bv.file.original_filename, ld_path=[
                                BackgroundTaskManager.ld_path], use_sim_procedures=False, use_system_libs=False)
            libs = list(proj.loader.shared_objects.keys())[1::]
            mapped_libs = {}
            for i in range(0, len(libs)):
                mapped_libs[i] = libs[i]
            selected = interaction.get_choice_input(
                "Libraries", "project libraries", libs)
            binja.log_info("Selected library {0}".format(
                mapped_libs[selected]))
            BackgroundTaskManager.selected_opt = mapped_libs[selected]
        except KeyError:
            UIPlugin.display_message(
                'KeyException', "Library was not selected")

    @classmethod
    def dump_regs(self, state, registers, *include):
        """
        Parameters
        ----------
        state : angr.SimState
           current state of execution
        registers : list
            list of registers
        *include : variable list
            variable list of registers, override registers list
        """

        data = []
        if(len(include) > 0):
            data = [x for x in registers if x in include]
        else:
            data = registers
        for reg in data:
            regv = state.regs.get(reg)
            if hasattr(regv, "__len__") and len(regv) > 100:
                regv = "<TOO LONG>"
            binja.log_info("${0}: {1}".format(reg, regv))

    @classmethod
    def color_path(self, bv, addr):
        """
        Parameters
        ----------
        bv : BinaryView instance
        address : BinaryView address
        """
        
        # Highlight the instruction in green
        blocks = bv.get_basic_blocks_at(addr)
        UIPlugin.path.append(addr)
        for block in blocks:
            block.set_auto_highlight(HighlightColor(
                HighlightStandardColor.GreenHighlightColor, alpha=128))
            block.function.set_auto_instr_highlight(
                addr, HighlightStandardColor.GreenHighlightColor)

    @classmethod
    def clear_color_path(self, bv):
        """
        Parameters
        ----------
        bv : BinaryView instance
        """

        if(len(UIPlugin.path) <= 0):
            UIPlugin.display_message("Path", "Nothing to clear yet")
            return
        for addr in UIPlugin.path:
            blocks = bv.get_basic_blocks_at(addr)
            for block in blocks:
                block.set_auto_highlight(HighlightColor(
                    HighlightStandardColor.NoHighlightColor, alpha=128))
                block.function.set_auto_instr_highlight(
                    addr, HighlightStandardColor.NoHighlightColor)

    def set_start_address(self, bv, addr):
        """
        Parameters
        ----------
        bv : BinaryView instance
        address : BinaryView address
        """

        try:
            blocks = bv.get_basic_blocks_at(addr)
            for block in blocks:
                if(addr != self.start and self.start != None):
                    block.function.set_auto_instr_highlight(
                        self.start, HighlightStandardColor.NoHighlightColor)
                    block.function.set_auto_instr_highlight(
                        addr, HighlightStandardColor.OrangeHighlightColor)
                    self.start = addr
                    BackgroundTaskManager.start_addr = self.start
                else:
                    block.function.set_auto_instr_highlight(
                        addr, HighlightStandardColor.OrangeHighlightColor)
                    self.start = addr
                    BackgroundTaskManager.start_addr = self.start
                    BackgroundTaskManager.prototype = get_named_type(block.function)
            binja.log_info("Start: 0x%x" % addr)
        except:
            show_message_box("StartAddress", "Error please open git issue !",
                             MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)

    def _clear_address(self, block, addr):
        """
        Parameters
        ----------
        bv : BinaryView instance
        address : BinaryView address
        """

        for x in block:
            x.function.set_auto_instr_highlight(
                addr, HighlightStandardColor.NoHighlightColor)
        addr = None

    def clear_start_address(self, bv):
        """
        Parameters
        ----------
        bv : BinaryView instance
        """

        if self.start:
            start_block = bv.get_basic_blocks_at(self.start)
            self._clear_address(start_block, self.start)
            self.start = None
            BackgroundTaskManager.start_addr = self.start
        else:
            show_message_box("Plugin", "Start address not set !",
                             MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.WarningIcon)
            return

    def set_avoid_address(self, bv, addr):
        """
        Parameters
        ----------
        bv : BinaryView instance
        address : BinaryView address
        """

        try:
            blocks = bv.get_basic_blocks_at(addr)
            for block in blocks:
                if(addr not in self.avoid and self.avoid):
                    # TODO: more avoid addresses?
                    block.function.set_auto_instr_highlight(
                        addr, HighlightStandardColor.RedHighlightColor)
                    self.avoid.add(addr)
                    BackgroundTaskManager.avoid_addr.add(self.avoid)
                else:
                    block.function.set_auto_instr_highlight(
                        addr, HighlightStandardColor.RedHighlightColor)
                    self.avoid.add(addr)
                    BackgroundTaskManager.avoid.add(self.avoid)
            binja.log_info("Avoid: 0x%x" % addr)
        except:
            show_message_box("Plugin", "Error please open git issue !",
                             MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)

    def clear_avoid_address(self, bv):
        """
        Parameters
        ----------
        bv : BinaryView instance
        """
        
        if self.avoid:
            for addr in self.avoid:
                end_block = bv.get_basic_blocks_at(addr)
                self._avoid_address(end_block, addr)
                self.avoid.remove(addr)
                BackgroundTaskManager.avoid.remove(addr)
        else:
            show_message_box("Plugin", "Avoid addresses not set !",
                             MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.WarningIcon)
            return

    def set_end_address(self, bv, addr):
        """
        Parameters
        ----------
        bv : BinaryView instance
        address : BinaryView address
        """

        try:
            blocks = bv.get_basic_blocks_at(addr)
            for block in blocks:
                if(addr != self.end and self.end != None):
                    block.function.set_auto_instr_highlight(
                        self.end, HighlightStandardColor.NoHighlightColor)
                    block.function.set_auto_instr_highlight(
                        addr, HighlightStandardColor.OrangeHighlightColor)
                    self.end = addr
                    BackgroundTaskManager.end_addr = self.end
                else:
                    block.function.set_auto_instr_highlight(
                        addr, HighlightStandardColor.OrangeHighlightColor)
                    self.end = addr
                    BackgroundTaskManager.end_addr = self.end
            binja.log_info("End: 0x%x" % addr)
        except:
            show_message_box("Plugin", "Error please open git issue !",
                             MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)

    def clear_end_address(self, bv):
        """
        Parameters
        ----------
        bv : BinaryView instance
        """
        
        if self.end:
            end_block = bv.get_basic_blocks_at(self.end)
            self._clear_address(end_block, self.end)
            self.end = None
            BackgroundTaskManager.end_addr = self.end
        else:
            show_message_box("Plugin", "End address not set !",
                             MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.WarningIcon)
            return

    @classmethod
    def display_message(self, title, desc):
        """
        Parameters
        ----------
        title : string
            title for message box
        desc: string
            description for message box
        """

        show_message_box(title, desc,
                         MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.WarningIcon)

    def _mapper(self, params):
        """
        Parameters
        ----------
        params : list
           list of parameters type that function accepts

        Return
        ------
            Mapped types
        """


        types = {
            0: 'void',
            1: 'bool',
            2: 'integer',
            3: 'float',
            4: 'structure',
            5: 'enum',
            6: 'pointer',
            7: 'array',
            8: 'function',
            9: 'var_args',
            10: 'value',
            11: 'named_reference',
            12: 'wide_char'
        }
        mapped_types = []
        for param in params:
            mapped_types.append(
                {'param': param.name, 'type': types[param.type.type_class], \
                 'value': None, 'b_overflow': 0, 'pattern_create': 0, \
                 'symbolic': 0, 'printable': 1, 'len':1024})
        return mapped_types

    def _generate_menu_text_fields(self, arg_types):
        """
        Parameters
        ----------
        arg_types : list
            list of converted by mapper function params to display
        
        Return
        ------
            UI menu
        """

        menu = ["Function Params"]
        for arg in arg_types:
            if arg['type'] == 'integer':
                text_field = interaction.IntegerField("{0} => type: {1}".format(arg['param'], arg['type']))
            else:
                text_field = interaction.TextLineField("{0} => type: {1}".format(arg['param'], arg['type']))
            # TODO may run 2 times: concrete and symbolic
            overflow_field = interaction.ChoiceField(
                "Run with symbolic memory corruption checker", ["No", "Yes"])
            pattern_field = interaction.ChoiceField(
                "Send Pattern", ["No", "Yes"])
            symbolic_field = interaction.ChoiceField(
                "Symbolic", ["No", "Yes"])
            printable_field = interaction.ChoiceField(
                "printable", ["No", "Yes"])
            len_field = interaction.IntegerField("len", default=1024)
            self.number_of_fields = 6
            menu.append(text_field)
            menu.append(overflow_field)
            menu.append(pattern_field)
            menu.append(symbolic_field)
            menu.append(printable_field)
            menu.append(len_field)
        return menu

    def _get_menu_results(self, menu_items, param_num):
        """
        Parameters
        ----------
        menu_items : list
            list of results after user provided data
        param_num: integer
            number of function params
        
        Return
        ------
           list of dictionaries per function parameter
        """

        result = [x.result for x in menu_items]
        keys = ['value', 'b_overflow', 'pattern_create', 'symbolic', 'printable', 'len'] * param_num
        return list(zip(keys, result))

    def _convert_menu_results(self, input_data, mapped_types, size):
        """
        Parameters
        ----------
        input_data : list
            list of results provided by _get_menu_results function
        mapped_types: list
            list of mapped types to params
        size: integer
            number of unique keys that were added by _get_menu_results
        
        Return
        ------
            list of mapped types and values for supported key:value pairs
        """
        binja.log_debug(f"input_data: {input_data}")
        binja.log_debug(f"mapped_types: {mapped_types}")
        binja.log_debug(f"size: {size}")
        result = []
        temp = [{item[0]:item[1]} for item in input_data]
        binja.log_debug(f"temp:{temp}")
        for i in range(0, len(temp), size):
            # TODO: make it not hardcoded
            d1 = dict(temp[i:i+size][0], **temp[i:i+size][1])
            d2 = dict(temp[i:i+size][1], **temp[i:i+size][2])
            d3 = dict(temp[i:i+size][2], **temp[i:i+size][3])
            d4 = dict(temp[i:i+size][3], **temp[i:i+size][4])
            d5 = dict(temp[i:i+size][4], **temp[i:i+size][5])
            result.append(dict(d1, **dict(d2, **dict(d3, **dict(d4, **d5)))))
        binja.log_debug(f"result:{result}")
        for i in range(0, len(mapped_types)):
            for k, v in mapped_types[i].items():
                if k == 'b_overflow' or k == 'value' or k == 'pattern_create' \
                    or k == 'symbolic' or k=='printable' or k=='len':
                    mapped_types[i][k] = result[i][k]
        return mapped_types



    def step_up(self, var, func_caller, visited, level=0):
        visited.add(func_caller)
        if isinstance(var, binja.variable.Variable):
            next_instr = func_caller.mlil.get_var_definitions(var)[0]
        else:
            next_instr = func_caller.mlil.get_ssa_var_definition(var)
        if next_instr:
            print(indent(level),hex(next_instr.address), next_instr)
            var_read = next_instr.ssa_form.vars_read
            if var_read:
                for v in var_read:
                    print(indent(level),v)
                    self.step_up(v, func_caller,visited, level+1)


    def find_arg_origin(self, bv, func):
        """
        Parameters
        ----------
        bv : BinaryView instance
        addr: BinaryView address
        """
        #func = bv.get_function_at(addr)
        #binja.log_debug('addr', hex(addr))
        # if(func == None or type(func) != binja.function.Function):
        #     print(f"{func} {type(func)}")
        #     self.display_message("Error", "This is not a function!")
        #     return
        # func_symbol = bv.get_symbol_by_raw_name("strcpy")
        # func_refs = [(ref.function, ref.address) for ref in bv.get_code_refs(func_symbol.address)]
        #func_refs = [ (ref.function, ref.address) for ref in bv.get_code_refs(bv.symbols[func.name].address)]
        refs = [bv.get_code_refs(x.address) for x in bv.symbols.get(func.name)]
        func_refs = [(item.function, item.address) for sublist in refs for item in sublist]
        print("[*] func refs", func_refs)
        for function, addr in func_refs:
            try:
                func_ssa = function.get_low_level_il_at(addr).mlil.ssa_form
                binja.log_info("[+] Function {}@{} as SSA {}".format(
                    function.name,hex(function.start),func_ssa))
                for param in func_ssa.params:
                    visited = set()
                    print("Current param {0}".format(param))
                    if function in visited:
                        binja.log_info(f"Already visited:{function}")
                        continue
                    else:
                        self.step_up(param.src, function,visited)
            except AttributeError as e:
                binja.log_info("Error, {0}".format(e))
                pass

        # binja.log_info("Func callers {0}".format(func.callers))
        # func_caller = func.callers[0]
        # if not func_caller:
        #     self.display_message("Error", "No callers found!")
        #     return
        # binja.log_info("[+] Function caller: {0}".format(
        #     func_caller))
        # try:
        #     func_ssa = func_caller.get_low_level_il_at(BackgroundTaskManager.start_addr).mlil.ssa_form
        #     binja.log_info("[+] Function as SSA {0}".format(
        #         func_ssa))
        #     for param in func_ssa.params:
        #             print("Current param {0}".format(param))
        #             self.step_up(param.src, func_caller)
        # except AttributeError as e:
        #     binja.log_info("Error, {0}".format(e))
        #     pass

    def set_function_params(self, bv, func):
        """
        Parameters
        ----------
        bv : BinaryView instance
        addr: BinaryView address
        """
        # func = bv.get_function_at(addr)
        # if(func == None or type(func) != binja.function.Function):
        #     self.display_message("Error", "This is not a function!")
        #     return
        params_len = len(func.parameter_vars)
        binja.log_info("[+] Function has {0} params".format(
            params_len))
        if params_len <= 0:
            UIPlugin.display_message(
                "Params", "This function do not take any params")
            return
        mapped_types = self._mapper(func.parameter_vars)
        menu_items = self._generate_menu_text_fields(mapped_types)
        menu = interaction.get_form_input(menu_items, "Parameters")
        if menu:
            results = self._get_menu_results(menu_items[1::], params_len)
            converted = self._convert_menu_results(results, mapped_types, self.number_of_fields)
            # self._make_symbolic(converted)
            # self._pattern_create(converted)
            # self._display_converted_params(converted)
            BackgroundTaskManager.func_params = converted

    @classmethod
    def clear(self, bv):
        """
        Parameters
        ----------
        bv : BinaryView instance
        """

        UIPlugin.clear_color_path(bv)
        BackgroundTaskManager.start_addr = 0x0
        BackgroundTaskManager.end_addr = 0x0
        BackgroundTaskManager.func_params = {}
        BackgroundTaskManager.selected_opt = ''
        BackgroundTaskManager.ld_path = ''


class AngrRunner(BackgroundTaskThread):
    """
    Class is used to execute run method on Explorer instances
    
    Methods
    -------
    run()
        public, execute Explorer instances run method
    
    Params
    ------
    explorer - instance created from inherited Explorer class like(ROPExplorer or VulnerabilityExplorer)
    """

    def __init__(self, bv, explorer):
        BackgroundTaskThread.__init__(
            self, "Vulnerability research with angr started...", can_cancel=True)
        self.bv = bv
        self.explorer = explorer

    def run(self):
        self.explorer.run()

    @classmethod
    def cancel(self, bv):
        UIPlugin.clear_color_path(bv)


class BackgroundTaskManager():
    """
    Class is used to execute run method on Explorer instances
    
    Methods
    -------
    set_exploit_payload(self, init, payload)
        public, sets payload for JSONExploitCreator or FileCreator
    
    def _get_endianess(self, bv)
        private protected, set endianness base on binary information

    vuln_explore(self,bv)
        public, create instance of VulnerabilityExplorer and pass to AngrRunner to execute

    build_rop(self, bv)
        public, create instance of ROPExplorer and pass to AngrRunner to execute
    
    exploit_to_file(self, bv)
        public, save generated explioit to file
   
    exploit_to_json(self, bv):
        public, save generated exploit to JSON

    stop(self, bv):
        public, stop execution
    
    Fields
    ------
    start_addr: BinaryView address

    end_addr: BinaryView address

    ld_path:string
        selected path from shared libraries

    func_params: dictionary
        keeps all function parameters with mapping

    selected_opt: string
        selected library to load by UIPlugin
    """
    
    start_addr = 0x0
    end_addr = 0x0
    ld_path = ''
    func_params = {}
    selected_opt = ''

    def __init__(self):
        self.runner = None
        self.vulnerability_explorer = None
        self.rop_explorer = None
        self.exploit_creator = None
        self.json_exploit_creator = None
        self.proj = None
        self.init = None
        self.libc_base = None
        self.payload = None

    @classmethod
    def set_exploit_payload(self, init, payload):
        """
        Parameters
        ----------
        init : string
            initial payload

        payload: string
            payload after ROP
        
        """
        self.payload = payload
        self.init = init

    @classmethod
    def _get_endianess(self, bv):
        """
        Parameters
        ----------
        bv : BinaryView instance

        Return
        ------
            endianess as string
        """

        if bv.arch.endianness == 1:
            return 'big'
        return 'little'


    def vuln_explore(self, bv):
        """
        Parameters
        ----------
        bv : BinaryView instance
        """
        try:
            start_addr = BackgroundTaskManager.start_addr
            end_addr = BackgroundTaskManager.end_addr
            ld_path = BackgroundTaskManager.ld_path
            params = BackgroundTaskManager.func_params
            if(start_addr == 0x0 or end_addr == 0x0):
                UIPlugin.display_message(
                    'TypeError', "Invalid or missing start_addr or end_addr")
                return
            print("BackgroundTaskManager start_addr: 0x{0:0x}, end_addr: 0x{1:0x}".format(
                start_addr, end_addr))
            self.vulnerability_explorer = VulnerabilityExplorer(
                bv, BackgroundTaskManager.start_addr, BackgroundTaskManager.end_addr,\
                    BackgroundTaskManager.prototype, \
                    ld_path=ld_path)
            binja.log_info("Session function params {0}".format(params))
            args = self.vulnerability_explorer.set_args(params)
            func_params = self.vulnerability_explorer.get_params_list(
                args, len(args.keys()))
            binja.log_info(
                "Parameters pass to function {0}".format(func_params))
            state = self.vulnerability_explorer.feed_function_state(
                func_params)
            self.vulnerability_explorer.set_sim_manager(state)
            result = self.vulnerability_explorer.check_buffer_overflow(params)
            if result == False:
                UIPlugin.display_message(
                    'Buffer Overflow Check', "Only one parameter could be check for Buffer Overflow")
                return
            self.runner = AngrRunner(bv, self.vulnerability_explorer)
            self.runner.start()
        except KeyError as e:
            UIPlugin.display_message(
                'KeyError', "Missing definition of: {0}".format(e))
            return

    def build_rop(self, bv):
        """
        Parameters
        ----------
        bv : BinaryView instance
        """

        try:
            endian = BackgroundTaskManager._get_endianess(bv)
            start_addr = BackgroundTaskManager.start_addr
            end_addr = BackgroundTaskManager.end_addr
            ld_path = BackgroundTaskManager.ld_path
            if(start_addr == 0x0 or end_addr == 0x0 or ld_path == ''):
                UIPlugin.display_message(
                    'TypeError', "Invalid or missing start_addr or end_addr or lib path")
                return
            print("BackrgoundTaskManager ld_path: {0}".format(ld_path))
            selected_opt = BackgroundTaskManager.selected_opt
            self.proj = angr.Project(bv.file.original_filename, use_sim_procedures=False, ld_path=[
                ld_path], use_system_libs=False)
            self.libc = self.proj.loader.shared_objects[selected_opt]
            print("LIBC", self.libc)
            self.libc_base = self.libc.min_addr
            self.gadget1 = self.libc_base+0x00055c60
            self.gadget2 = self.libc_base+0x00024ecc
            self.gadget3 = self.libc_base+0x0001e20c
            self.gadget4 = self.libc_base+0x000195f4
            self.gadget5 = self.libc_base+0x000154d8
            self.sleep = self.libc_base + 0x00053ca0

            self.init = b"A"*160 + b"BBBB" + \
                p32(self.gadget2, endian=endian) + \
                p32(self.gadget1, endian=endian)
            self.rop_explorer = ROPExplorer(bv, self.proj, start_addr, end_addr, init=self.init, first=self.gadget1, second=self.gadget2,
                                            third=self.gadget3, fourth=self.gadget4, fifth=self.gadget5, sixth=self.sleep)

            args = self.rop_explorer.set_args(
                arg0={'key': self.init, 'key_type': 'pointer'})
            state = self.rop_explorer.feed_function_state(args)
            self.rop_explorer.set_sim_manager(state)
            self.runner = AngrRunner(bv, self.rop_explorer)
            self.runner.start()
        except KeyError as e:
            UIPlugin.display_message(
                'KeyException', "Missing definition of: {0}".format(str(e)))

  
    def exploit_to_file(self, bv):
        """
        Parameters
        ----------
        bv : BinaryView instance
        """
        self.exploit_creator = FileExploitCreator(bv, self.init, self.payload)
        self.runner = AngrRunner(bv, self.exploit_creator)
        self.runner.start()
 
    @classmethod
    def exploit_to_json(self, bv, init, payload):
        """
        Parameters
        ----------
        bv : BinaryView instance
        """
        if payload:
            self.json_exploit_creator = JSONExploitCreator(
                bv, init, payload)
            self.runner = AngrRunner(bv, self.json_exploit_creator)
            self.runner.start()
        else:
            binja.log_warn("JSON payload issue {0}".format(payload))

    def stop(self, bv):
        """
        Parameters
        ----------
        bv : BinaryView instance
        """

        self.runner.cancel(bv)


class VulnerabilityExplorer(MainExplorer):
    """
    Class inherit from MainExplorer 

    Methods
    ----------
    explore(self, state)
        public, main angr find function 

    run(self)
        public protected, run angr exploration

    set_args(self, args)
        public protected, set real angr function params

    get_params_list(self, arg, size)
        public, get list of params

    _get_endianess(self, bv)
        private protected, get endianess of binary

    feed_function_state(self, params)
        public protected, feed function with state

    set_sim_manager(self, state)
        public protected, set sim manager instance

    check_buffer_overflow(self, params)
        public, check if any function params was set to check for buffer overflow condition

    _find_pattern(self, params, pattern)
        private, check for string pattern occurance
        
    identify_overflow(self, found, registers=[], silence=True, *exclude)
        private, check for buffer overflow condition

    get_vuln_report(self, report):
        private, get report of vulnerability
    """
    
    def __init__(self, bv, func_start_addr, func_end_addr, prototype, avoid_addresses=[], ld_path=[], use_system_libs=False, use_sim_procedures=False):
        binja.log_debug(f"Initializing VulnerabilityExplorer with params bv:{bv} start:{func_start_addr} end:{func_end_addr} prot:{prototype} avoid:{avoid_addresses} ld_path:{ld_path} use_system_libs:{use_system_libs} use_sim_procedures:{use_sim_procedures}")
        self.bv = bv
        self.arch = bv.arch.name
        self.use_sim_procedures = use_sim_procedures
        self.ld_path=ld_path
        self.use_sim_procedures=use_sim_procedures
        self.proj = angr.Project(self.bv.file.original_filename, use_sim_procedures=use_sim_procedures,\
            ld_path=ld_path, use_system_libs=use_system_libs)
        self.avoid_addresses = avoid_addresses
        self.func_start_addr = self.proj.loader.min_addr + func_start_addr
        self.func_end_addr = self.proj.loader.min_addr + func_end_addr
        self.prototype = prototype
        self.cfg = self.proj.analyses.CFG(regions=[(self.func_start_addr, self.func_end_addr)])
        self.args = {}
        self.overflow = False
        self.has_leak = False
        self.params = None
        self.proj.hook(self.func_end_addr, self.explore)

    def rva(self, addr):
        return addr - self.proj.loader.min_addr

    def explore(self, state):
        """
        Parameters
        ----------
        state : angr SimState
            current state of execution
        """
        binja.log_debug("Explore start")
        pc = state.solver.eval(state.regs.pc, cast_to=int)  
        binja.log_debug(f"Exploring PC:{hex(pc)} RVA:{hex(self.rva(pc))}")
        UIPlugin.color_path(self.bv, self.rva(pc))
        # we execute functions so let's check we passed return 
        # or got back to ret_addr
        if self.overflow:
            if pc == 0:
                print(f"Exploration finished! Came to 0x0 address")
                return True
        else:
            if pc == self.func_end_addr or pc == self.proj.loader.min_addr:
                print(f"Exploration finished! at {hex(pc)} RVA:{hex(self.rva(pc))}")
                #UIPlugin.dump_regs(state, registers[self.bv.arch.name])
                return True
        binja.log_debug("Explore end")

    # for debugging
    def step_debug(self, simgr):
        print("step")
        print("errored")
        print(simgr.errored)
        for state in simgr.errored:
            if hasattr(state.state,'history'):
                pprint.pprint(state.state.history.descriptions.hardcopy)
            else:
                pprint.pprint(state.state)
                pprint.pprint(state.error)
                pprint.pprint(state.traceback)
            #state.debug()
        print("active")
        for state in simgr.active:
            print(f"PC:{state.regs.pc}")
            if hasattr(state,'history'):
                pprint.pprint(state.history.descriptions.hardcopy)
            else:
                pprint.pprint(state)
        print("unconstrained")
        for state in simgr.unconstrained:
            print(f"PC:{state.regs.pc}")
            if hasattr(state,'history'):
                pprint.pprint(state.history.descriptions.hardcopy)
            else:
                pprint.pprint(state)
        return simgr
    
    def exploitable(self, state, reg='pc'):
        for i in range(state.arch.bits):
            if not state.solver.symbolic(state.regs.get(reg)[i]):
                return False
        return True
    
    def partially_exploitable(self, state, reg='pc'):
        count = 0
        for i in range(state.arch.bits):
            if state.solver.symbolic(state.regs.get(reg)[i]):
                print("Symbolic bit {} possible in {}".format(i, reg))
                count += 1
        return count
    
    def step_check_mem_corruption_symbolic(self, simgr):
        #self.step_debug(simgr)
        binja.log_debug("[*] Check symbolic memory corruption step")
        
        if simgr.unconstrained:
            print("[*] Step check mem corruption - unconstrained path")
            for path in simgr.unconstrained:
                if self.exploitable(path):
                    print(f"Fully exploitable at {path}")
                    simgr.stashes['mem_corrupt'].append(path)
                    simgr.drop(stash="active")
                    break
                if self.partially_exploitable(path):
                    print(f"Partially exploitable at {path}")
                    simgr.stashes['mem_corrupt'].append(path)
                    simgr.drop(stash="active")
                simgr.stashes["unconstrained"].remove(path)

        if simgr.errored:
            print("[*] Step check mem corruption - errored path")
            for err in simgr.errored:
                path = err.state
                print(path)
                if self.exploitable(path):
                    print(f"Fully exploitable at {path}")
                    simgr.stashes['mem_corrupt'].append(path)
                    simgr.drop(stash="active")
                    break
                if self.partially_exploitable(path):
                    print(f"Partially exploitable at {path}")
                    simgr.stashes['mem_corrupt'].append(path)
                    simgr.drop(stash="active")

        binja.log_debug("step done")
        return simgr

    def step_check_mem_corruption_pattern(self, simgr):
        binja.log_debug("[*] Check pattern memory corruption step")
        #self.step_debug(simgr)
        for state in simgr.active:
            pc = state.regs.pc
            pattern = state.solver.eval(pc.reversed, cast_to=bytes)
            pattern2 = state.solver.eval(pc, cast_to=bytes)
            if self._find_pattern(self.params, pattern):
                print(f"Memory corruption found at {pc} with value {pattern}")
                simgr.stashes["mem_corrupt"].append(state)
                simgr.drop(stash="active")
            if self._find_pattern(self.params, pattern2):
                print(f"Memory corruption found at {pc} with value {pattern2}")
                simgr.stashes["mem_corrupt"].append(state)
                simgr.drop(stash="active")
        binja.log_debug("step done")
        return simgr

    def check_stack_chk_fail(self, state):
        binja.log.log_error("Found a StackOverflow - catched by __stack_chk_fail")
        self.simgr.stashes["mem_corrupt"].append(state)
        #self.simgr.drop(stash="active")

    def analyze_printf_x86_64(self, state):
        # Check if rsi is not a string
        # If it isn't then we know the vulnerable printf statement
        # TODO: handle different architectures
        string = state.solver.eval(state.regs.rdi)
        varg = state.solver.eval(state.regs.rsi)
        address = state.solver.eval(state.regs.rip)

        return_target = state.callstack.current_return_target

        # If rdi is a stack or libc address
        if string >= 0xffffffffff:
            self.has_leak = True
            binja.log_error(f"[!] VULN: Found printf leak at {return_target}!")
            self.simgr.stashes["format_strings"].append(state)

    def generate_script_template(self):
        print("=====================SCRIPT TEMPLATE=========================")
        print(f"""
        START_ADDR = {hex(self.rva(self.func_start_addr))}
        END_ADDR = {hex(self.rva(self.func_end_addr))}
        PROTOTYPE = "{self.prototype}"
        AVOID = {self.avoid_addresses}
        LD_PATH = {self.ld_path}
        USE_SIM = {self.use_sim_procedures}
    """)
        print("=====================SCRIPT END=============================")
        

    def hook_printf(self):
        # may check for other logging functions
        print("Setting hook for printf")
        if self.arch == 'x86_64':
            if self.proj.loader.main_object.get_symbol("printf") is not None:
                self.proj.hook_symbol("printf", self.analyze_printf_x86_64)
        else:
            raise "Unsupported arch for printf hook!"

    def hook_stack_chk_fail(self):
        # TODO: some bug on MacOS in CLE
        print("Setting hook for __stack_chk_fail")
        symb = self.proj.loader.main_object.get_symbol("__stack_chk_fail") 
        if symb is not None:
            if isinstance(symb, list):
                binja.log.log_error("[-] Multiple symbols for stack_chk_fail found!")
            else:
                self.proj.hook_symbol("__stack_chk_fail", self.check_stack_chk_fail)

    def generate_avoid_addresses(self):
        avoid = []
        if self.overflow:
            print(f"Buffer overflow mode, adding {hex(self.proj.loader.min_addr)} to avoid addresses")
            avoid.append(self.proj.loader.min_addr)
        for addr in self.avoid_addresses:
            va = addr + self.proj.loader.min_addr
            print(f"Avoid address: {hex(va)}")
            avoid.append(va)
        return avoid

    def run(self):
        print("VulnerabilityExplorer start")
        self.generate_script_template()
        self.simgr.stashes["mem_corrupt"] = []
        self.simgr.stashes["format_strings"] = []

        self.hook_printf()
        self.hook_stack_chk_fail()

        if self.overflow:
            # use symbolic search for buffer overflows
            print("Running in Search For Overflow mode!")
            sm = self.simgr.explore(find=self.explore, avoid=self.generate_avoid_addresses(),\
                                    step_func=self.step_check_mem_corruption_symbolic, num_find=1,\
                                    cfg=self.cfg)
        else:
            # check with concrete pattern
            print("Running in normal mode!")
            sm = self.simgr.explore(find=self.explore,avoid=self.generate_avoid_addresses(),\
                                    step_func=self.step_check_mem_corruption_pattern, num_find=1, \
                                    cfg=self.cfg)
        test = sm.found
        print("Found states")
        print(test)
        if len(test) > 0:
            print("State found - stop", test)
            found = test[0]
            print(found)
            UIPlugin.dump_regs(found, registers[self.bv.arch.name]) 
            self._solve_symbolic_params(found)
            if self.overflow:
                self._identify_overflow_symbolic(found, registers[self.bv.arch.name])
            self._identify_overflow(found, registers[self.bv.arch.name])

        if len(self.simgr.stashes["mem_corrupt"])>0:
            print("Memory corruption state found!")
            found = self.simgr.stashes["mem_corrupt"][-1]
            print(found)
            UIPlugin.dump_regs(found, registers[self.bv.arch.name]) 
            self._solve_symbolic_params(found)
            if self.overflow:
                self._identify_overflow_symbolic(found, registers[self.bv.arch.name])
            self._identify_overflow(found, registers[self.bv.arch.name])

        if len(self.simgr.stashes["format_strings"])>0:
            print("Memory corruption state found!")
            found = self.simgr.stashes["format_strings"][-1]
            print(found)
            UIPlugin.dump_regs(found, registers[self.bv.arch.name]) 
            self._solve_symbolic_params(found)
            self._identify_overflow(found, registers[self.bv.arch.name])

        print("Errored states")
        for state in self.simgr.errored:
            # pprint.pprint(state.error)
            # pprint.pprint(state.traceback)
            # pprint.pprint(state.state)
            UIPlugin.dump_regs(state.state, registers[self.bv.arch.name]) 
            self._solve_symbolic_params(state.state)
            if self.overflow:
                self._identify_overflow_symbolic(state.state, registers[self.bv.arch.name])
            self._identify_overflow(state.state, registers[self.bv.arch.name])
            
        print("Unconstrainted states")
        for state in self.simgr.unconstrained:
            # pprint.pprint(state)
            UIPlugin.dump_regs(state, registers[self.bv.arch.name]) 
            self._solve_symbolic_params(state)
            if self.overflow:
                self._identify_overflow_symbolic(state, registers[self.bv.arch.name])
            self._identify_overflow(state, registers[self.bv.arch.name])

        print("Unsat states")
        if sm.unsat:
            print("[*] One of these is false: ", sm.unsat[0].solver.unsat_core())

        print("VulnerabilityExplorer done")

        
    def set_args(self, args):
        """
        Parameters
        ----------
        args : list
            list of parameters to be checked for pointer type
        Return
        ------
            dictionary of angr mapped parameters
        """
        
        binja.log.log_debug(f"set_args:{args}")
        self.original_args = args
        self._make_symbolic(args)
        self._pattern_create(args)
        counter = 0
        if args is not None:
            for item in args:
                if item['type'] == 'pointer':
                    # TODO: decode from hex escaped strings
                    v = item.get('value')
                    if not item.get('symbolic'): 
                        if v == "NULL":
                            binja.log_debug("{} is NULL pointer".format(item))
                            p = 0
                        else:
                            v = codecs.decode(v, "unicode_escape")
                            p = angr.PointerWrapper(v, buffer=True)
                    else:
                        p = angr.PointerWrapper(v, buffer=True)
                    self.args['arg'+str(counter)] = p
                else:
                    self.args['arg'+str(counter)] = item.get('value')
                counter += 1
        return self.args

    def get_params_list(self, args, size):
        """
        Parameters
        ----------
        args : list
            list of parameters to be checked for pointer type
        size: integer
            number of args
        Return
        ------
            list of function params named from agr0 to argX
        """

        possible_args = ['arg'+str(x) for x in range(0, size)]
        func_params = []
        for item in possible_args:
            if args.get(item) != None:
                func_params.append(args.get(item))
        return func_params

    def _get_endianess(self, bv):
        """
        Parameters
        ----------
        args : BinaryView instance
        """

        if bv.arch.endianness == 1:
            return 'big'
        return 'little'

    def _make_symbolic(self, params):
        """
        Parameters
        ----------
        params : list
            list of results after function params UI provided
        
        Return
        ------
            Return pattern string
        """

        plen = 0
        for p in params:
            if p['symbolic'] == 1:
                plen = p['len']
                binja.log_info("[+] symbolic size {}:{}".format(p['param'], plen))
                flag_chars = [claripy.BVS('symbolic_input_%d' % i, 8) for i in range(plen)]
                p['chars'] = flag_chars
                p['value'] = claripy.Concat(*flag_chars)
        return plen

    def _make_constraints(self, state, params):
        result = 0
        for p in params:
            if p['symbolic'] == 1:
                flag_chars = p['chars']
                if p['printable']:
                    for k in flag_chars:
                        state.solver.add(k <= 0x7f)
                        state.solver.add(k >= 0x20)

        binja.log_info("[+] symbolic size: {0}".format(result))
        return result
                
    def _pattern_create(self, params):
        """
        Parameters
        ----------
        params : list
            list of results after function params UI provided
        
        Return
        ------
            Return pattern string
        """

        counter = 0
        result = 0
        for p in params:
            if p['pattern_create'] == 1:
                counter += 1
        if counter >= 1:
            result = p['len']
            for p in params:
                if p['pattern_create'] == 1:
                    p['value'] = pattern_gen(result)
        binja.log_info("[+] pattern size: {0}".format(result))
        return result

    def _display_converted_params(self, params):
        """
        Parameters
        ----------
        params : list
            list of params to display at console log
        """
        for p in params:
            for k, v in p.items():
                if hasattr(v,'__len__') and len(v) > 512:
                    v = "<TOO LONG>"
                binja.log_info("[+] {0}: {1}".format(k, v))

    def _fix_buffers(self, state, params):
        for p in params:
            if p['symbolic']:
                l = p['len']
                state.libc.buf_symbolic_bytes = max(l, state.libc.buf_symbolic_bytes)
                state.libc.max_str_len = max(l, state.libc.max_str_len)
        print(f"buf_symbolic_bytes set to {hex(state.libc.buf_symbolic_bytes)}")
        print(f"max_strlen set to {hex(state.libc.max_str_len)}")


    def feed_function_state(self, params):
        """
        Parameters
        ----------
        params : list
            list of parameters to create function state
        Return
        ------
           angr function SimState state
        """
        binja.log_info(f"Starting function {hex(self.func_start_addr)} with prototype: {self.prototype}")
        binja.log_debug(f"Params:{params}")
        # self._make_symbolic(params)
        # self._pattern_create(params)
        # self._display_converted_params(params)
        self.state = self.proj.factory.call_state( \
            self.func_start_addr, *params, \
            ret_addr = self.proj.loader.min_addr,
            prototype=self.prototype, initial_prefix="ZZZ", \
            add_options=add_options)
        self._make_constraints(self.state, self.original_args)
        # TODO: check if doesn't break anything
        #self._fix_buffers(self.state, self.original_args)
        return self.state

    def set_sim_manager(self, state):
        """
        Parameters
        ----------
        state : angr SimState
            angr current SimState
        """
    
        self.simgr = self.proj.factory.simulation_manager(self.state, save_unconstrained=True)

    def check_buffer_overflow(self, params):
        """
        Parameters
        ----------
        params : list
            list of parameters to be checked for buffer overflow flag
        Return
        ------
            True if any parameter was set to check buffer overflow condition
        """
        if params:
            self.params = params
        counter = 0
        for item in params:
            if item['b_overflow'] == 1:
                counter += 1
        if counter == 1:
            self.overflow = True
            return self.overflow
        elif counter > 1:
            self.overflow = False
            return self.overflow

    def _find_pattern(self, params, pattern):
        """
        Parameters
        ----------
        params : list
            list of parameters to be checked for pattern

        pattern: string
            pattern to be searched

        Return
        ------
            True if pattern find
        """

        # TODO: pattern should be printable
        # may add additional parameter for that
        try:
            if isinstance(pattern, bytes):
                pattern = pattern.decode("ascii")
        except:
            return False

        try:
            return cyclic.cyclic_find(pattern, len(pattern)) > -1
        except:
            return cyclic.cyclic_find(pattern) > -1

    def _solve_symbolic_param(self,  copypath, key, symbolic_input):
        # print(f"Solving for path:{copypath} symb:{symbolic_input}")
        solution = copypath.solver.eval(symbolic_input, cast_to=bytes)
        binja.log_warn(
            "[*] Solution found {}:{}".format(key, solution))

    def _solve_symbolic_params(self, copypath):
        for param in self.params:
            if param['symbolic']:
                self._solve_symbolic_param(copypath, param['param'], param['value'])

    def _solve_symbolic_param_for_reg(self, arg, copypath, symbolic_input, report):
        # print(f"Solving for arg:{arg} path:{copypath} symb:{symbolic_input}")
        stack_smash = copypath.solver.eval(symbolic_input, cast_to=bytes)
        try:
            index = stack_smash.index(b"BBBBBBBB")
            self.symbolic_padding = stack_smash[:index]
            binja.log.log_info(f"Found symbolic padding: {self.symbolic_padding}")
            binja.log.log_info(f"Successfully Smashed the Stack, Takes {len(self.symbolic_padding)} bytes to smash the instruction pointer")
        except ValueError:
            binja.log.log_warn(f"Could not find index of {arg} overwrite")
            return
        
        # TODO: is_pc_register
        if((arg == 'rip' or arg=='rbp')):
            binja.log_warn("[*] Buffer overflow detected !!!")
            binja.log_warn(
                "[*] We can control ${0} using {1} as payload !!!!".format(arg, stack_smash))
            report[arg] = stack_smash
        else:
            binja.log_warn(
                "[+] Register ${0} overwritten using {1} as payload".format(arg, stack_smash))
            report[arg] = stack_smash
    
    def _solve_symbolic_params_for_reg(self, arg, copypath, report):
        for param in self.params:
            if param['symbolic']:
                self._solve_symbolic_param_for_reg(arg, copypath, param['value'], report)

    def _identify_overflow_symbolic(self, found, registers=[], silence=False, *exclude):
        """
        Parameters
        ----------
        found : angr SimState 

        registers: list
            list of CPU registers for binary
        
        silence: boolean
            if True log will display even if overflow not found

        *exclude: variable list
            list of CPU registers to exclude from overflow lookup
        """
    
        print("Trying to identify overflow by symbolic!")
        data = []
        report = {}
        if(len(exclude) > 0):
            data = [x for x in registers if x not in exclude]
        else:
            data = registers
        binja.log_debug("Registers to check:{}".format(",".join(data)))
        for arg in data:
            print("arg:{}".format(arg))
            binja.log_debug("reg:{}".format(found.regs.get(arg)))
            binja.log_debug("params:{}".format(self.params))
            copypath = found.copy()
            regv = copypath.regs.get(arg)
            print(f"regv:{regv}")
            copypath.add_constraints( regv == b'BBBBBBBB')
            print(copypath)
            if copypath.satisfiable():
                binja.log_debug("satisfiable")
                self._solve_symbolic_params_for_reg(arg, copypath, report)
            else:
                if(not silence):
                    binja.log_info(
                        "[-] Register ${0} is not controlled by ANGR".format(arg))
        if(bool(report)):
            interaction.show_markdown_report(
                "Vulnerability Info Report", self.get_vuln_report(report))
        print("Trying to identify overflow symbolic end!")


    def _identify_overflow(self, found, registers=[], silence=False, *exclude):
        """
        Parameters
        ----------
        found : angr SimState 

        registers: list
            list of CPU registers for binary
        
        silence: boolean
            if True log will display even if overflow not found

        *exclude: variable list
            list of CPU registers to exclude from overflow lookup
        """
    
        print("Trying to identify overflow!")
        data = []
        report = {}
        if(len(exclude) > 0):
            data = [x for x in registers if x not in exclude]
        else:
            data = registers
        binja.log_debug("Registers to check:{}".format(",".join(data)))
        for arg in data:
            pattern = found.solver.eval(found.regs.get(arg).reversed, cast_to=bytes)
            pattern2 = found.solver.eval(found.regs.get(arg), cast_to=bytes)
            binja.log_debug("arg:{}".format(arg))
            binja.log_debug("pattern:{}".format(pattern))
            binja.log_debug("params:{}".format(self.params))
            if self._find_pattern(self.params, pattern) or self._find_pattern(self.params, pattern2):
                # TODO: arch specific PC
                if((arg == 'rip' or arg=='rbp') and pattern_search(pattern.decode())):
                    binja.log_warn("[*] Buffer overflow detected !!!")
                    binja.log_warn(
                        "[*] We can control ${0} using {1} as payload !!!!".format(arg, pattern_search(pattern.decode())))
                    report[arg] = pattern_search(pattern.decode())
                else:
                    binja.log_warn(
                        "[+] Register ${0} overwritten using {1} as payload".format(arg, pattern_search(pattern.decode())))
                    report[arg] = pattern_search(pattern.decode())
            else:
                if(not silence):
                    binja.log_info(
                        "[-] Register ${0} not overwriten by pattern".format(arg))
        if(bool(report)):
            interaction.show_markdown_report(
                "Vulnerability Info Report", self.get_vuln_report(report))
        binja.log_debug("Trying to identify overflow end!")

    def get_vuln_report(self, report):
        """
        Parameters
        ----------
        report : dictionary
            holds data to be displayed for report

        Return
        ------
            vulnerability report

        """

        contents = "==== Vulnerability Report ====\r\n\n"
        for key, value in report.items():
            if(key == 'rip' or key=='ra'):
                contents += "[*] Buffer overflow detected !!!\r\n\n"
                contents += "We can control ${0} after {1} bytes !!!!\r\n\n".format(
                    key, value)
            else:
                contents += "Register ${0} overwritten after {1} bytes !!!!\r\n\n".format(
                    key, value)
        return contents


class ROPExplorer(MainExplorer):
    def __init__(self, bv, project, func_start_addr, func_end_addr, prototype, **kwargs):
        self.bv = bv
        self.func_start_addr = func_start_addr
        self.func_end_addr = func_end_addr
        self.prototype = prototype
        self.proj = project
        self.proj.analyses.CFGFast(
            regions=[(self.func_start_addr, self.func_end_addr)])
        self.init = kwargs['init']
        self.args = {}
        self.gadget1 = kwargs['first']
        self.gadget2 = kwargs['second']
        self.gadget3 = kwargs['third']
        self.gadget4 = kwargs['fourth']
        self.gadget5 = kwargs['fifth']
        self.sleep = kwargs['sixth']
        self.state_history = collections.OrderedDict()
        self.payload = collections.OrderedDict()
        self.endian = self._get_endianess(bv)

        binja.log_info("Gadget 1 address: 0x{0:0x}".format(self.gadget1))
        binja.log_info("Gadget 2 address: 0x{0:0x}".format(self.gadget2))
        binja.log_info("Gadget 3 address: 0x{0:0x}".format(self.gadget3))
        binja.log_info("Sleep func address: 0x{0:0x}".format(self.sleep))
        binja.log_info("Gadget 4 address: 0x{0:0x}".format(self.gadget4))
        binja.log_info("Gadget 5 address: 0x{0:0x}".format(self.gadget5))

        self.proj.hook(self.func_end_addr, self.overwrite_ra)
        self.proj.hook(self.gadget1, self.hook_gadget1)
        self.proj.hook(self.gadget2, self.hook_gadget2)  # jalr $t9
        # lw $s1, 0x28($sp)
        self.proj.hook(self.gadget2+4, self.hook_gadget2next4)
        # lw $s0, 0x24($sp)
        self.proj.hook(self.gadget2+8, self.hook_gadget2next8)
        self.proj.hook(self.gadget3, self.hook_gadget3)  # mov $t9, $s1
        # lw $ra, 0x24($sp)
        self.proj.hook(self.gadget3+4, self.hook_gadget3next4)
        # lw $s2, 0x20($sp)
        self.proj.hook(self.gadget3+8, self.hook_gadget3next8)
        # lw $s1, 0x1c($sp)
        self.proj.hook(self.gadget3+12, self.hook_gadget3next12)
        # lw $s0, 0x18($sp)
        self.proj.hook(self.gadget3+16, self.hook_gadget3next16)
        self.proj.hook(self.gadget4, self.hook_gadget4)  # addiu $s0, $sp, 0x24
        self.proj.hook(self.gadget5+4, self.explore)  # jalr $

    def set_args(self, **args):
        if args is not None:
            for key, value in args.items():
                if(type(value) == dict):
                    key_type = value.get('key_type')
                    if key_type == 'pointer':
                        p = angr.PointerWrapper(item.get('key'), buffer=True)
                        self.args[key] = p
                else:
                    self.args[key] = value
        return self.args

    def _get_endianess(self, bv):
        if bv.arch.endianness == 1:
            return 'big'
        return 'little'

    def feed_function_state(self, args=None, data=None):
        self.state = self.proj.factory.call_state(
            self.func_start_addr, args['arg1'], \
            ret_addr=MAGIC_RETADDR, prototype=self.prototype, \
            initial_prefix="ZZZ", add_options=add_options)
        return self.state

    def set_sim_manager(self, state):
        self.simgr = self.proj.factory.simulation_manager(self.state, save_unconstrained=True)

    def get_rop_report(self, state, data, gadget):
        contents = "==== 0x{0:0x} Registers ====\r\n\n".format(gadget)
        for reg in data:
            contents += "${0}: 0x{1:0x}\r\n\n".format(
                reg, state.solver.eval(state.regs.get(reg), cast_to=int))
        return contents

    def get_stack_report(self, data):
        contents = "====Stack Data ====\r\n\n"
        for key, value in data.items():
            contents += "{0}: {1}\r\n\n".format(key.decode(),
                                                u32(value, endian=self.endian))
        return contents

    def stack_adjust(self, state, reg, size, data="EEEE", vector_size=32):
        if(size >= 0):
            for i in range(4, size+4, 4):
                state.memory.store(reg+i, state.solver.BVV(data, 32))
                self.payload[hex(reg+i).encode()] = data.encode()

    def overwrite_ra(self, state):
        pc = state.solver.eval(state.regs.pc, cast_to=int)
        UIPlugin.color_path(self.bv, pc)
        if pc == self.func_end_addr:
            self.state_history['init'] = state

    def hook_gadget1(self, state):
        pc = state.solver.eval(state.regs.pc, cast_to=int)
        if pc == self.gadget1:
            self.state_history[hex(self.gadget1)] = state

    def hook_gadget2(self, state):
        pc = state.solver.eval(state.regs.pc, cast_to=int)
        if pc == self.gadget2:
            sp = state.solver.eval(state.regs.sp, cast_to=int)
            self.stack_adjust(state, sp, 0x20, "EEEE")
            # lw $ra, 0x2c($sp)
            state.memory.store(sp+0x2c, state.solver.BVV(self.gadget3, 32))
            self.payload[hex(sp+0x2c).encode()
                         ] = p32(self.gadget3, endian=self.endian)
            self.state_history[hex(self.gadget2)] = state

    def hook_gadget2next4(self, state):
        pc = state.solver.eval(state.regs.pc, cast_to=int)
        if pc == self.gadget2+4:
            sp = state.solver.eval(state.regs.sp, cast_to=int)
            # lw $s1, 0x28($sp)
            state.memory.store(sp+0x28, state.solver.BVV(self.sleep, 32))
            self.payload[hex(sp+0x28).encode()
                         ] = p32(self.sleep, endian=self.endian)

    def hook_gadget2next8(self, state):
        pc = state.solver.eval(state.regs.pc, cast_to=int)
        if pc == self.gadget2+8:
            sp = state.solver.eval(state.regs.sp, cast_to=int)
            # lw $s0, 0x24($sp)
            state.memory.store(sp+0x24, state.solver.BVV("DDDD", 32))
            self.payload[hex(sp+0x24).encode()] = b'DDDD'

    def hook_gadget3(self, state):
        pc = state.solver.eval(state.regs.pc, cast_to=int)
        if pc == self.gadget3:
            sp = state.solver.eval(state.regs.sp, cast_to=int)
            self.stack_adjust(state, sp, 0x18, "GGGG")
            # gadget3 -> lw $s0, 0x18($sp) => 24 bytes
            self.state_history[hex(self.gadget3)] = state

    def hook_gadget3next4(self, state):
        pc = state.solver.eval(state.regs.pc, cast_to=int)
        if pc == self.gadget3+4:
            sp = state.solver.eval(state.regs.sp, cast_to=int)
            # lw $ra, 0x24($sp)
            state.memory.store(sp+0x24, state.solver.BVV(self.gadget4, 32))
            self.payload[hex(sp+0x24).encode()
                         ] = p32(self.gadget4, endian=self.endian)

    def hook_gadget3next8(self, state):
        pc = state.solver.eval(state.regs.pc, cast_to=int)
        if pc == self.gadget3+8:
            sp = state.solver.eval(state.regs.sp, cast_to=int)
            # lw $s2, 0x20($sp)
            state.memory.store(sp+0x20, state.solver.BVV("CCCC", 32))
            self.payload[hex(sp+0x20).encode()] = b'CCCC'

    def hook_gadget3next12(self, state):
        pc = state.solver.eval(state.regs.pc, cast_to=int)
        if pc == self.gadget3+12:
            sp = state.solver.eval(state.regs.sp, cast_to=int)
            # lw $s1, 0x1c($sp)
            state.memory.store(sp+0x1c, state.solver.BVV(self.gadget5, 32))
            self.payload[hex(sp+0x1c).encode()
                         ] = p32(self.gadget5, endian=self.endian)

    def hook_gadget3next16(self, state):
        pc = state.solver.eval(state.regs.pc, cast_to=int)
        if pc == self.gadget3+16:
            sp = state.solver.eval(state.regs.sp, cast_to=int)
            # lw $s0, 0x18($sp)
            state.memory.store(sp+0x18, state.solver.BVV("FFFF", 32))
            self.payload[hex(sp+0x18).encode()] = b'FFFF'

    def hook_gadget4(self, state):
        pc = state.solver.eval(state.regs.pc, cast_to=int)
        if pc == self.gadget4:
            sp = state.solver.eval(state.regs.sp, cast_to=int)
            # addiu $s0, $sp, 0x24
            state.memory.store(sp+0x24, state.solver.BVV("SHEL", 32))
            self.payload[hex(sp+0x24).encode()] = b'SHEL'
            self.state_history[hex(self.gadget4)] = state

    def explore(self, state):
        pc = state.solver.eval(state.regs.pc, cast_to=int)
        if pc == self.gadget5+4:
            return True

    def run(self):
        sm = self.simgr.explore(find=self.explore)
        test = sm.found
        if len(test) > 0:
            print(sm.found)
            found = sm.found[-1]
            print("found", found)
            UIPlugin.dump_regs(found, registers[self.bv.arch.name])

        # Generate raport for gadgets

            interaction.show_markdown_report("Initial State", self.get_rop_report(
                self.state_history['init'], registers[self.bv.arch.name], self.func_end_addr))
            interaction.show_markdown_report("ROP Gadget 1", self.get_rop_report(
                self.state_history[hex(self.gadget1)], registers[self.bv.arch.name], self.gadget1))
            interaction.show_markdown_report("ROP Gadget 2", self.get_rop_report(
                self.state_history[hex(self.gadget2)], registers[self.bv.arch.name], self.gadget2))
            interaction.show_markdown_report("ROP Gadget 3", self.get_rop_report(
                self.state_history[hex(self.gadget3)], registers[self.bv.arch.name], self.gadget3))
            interaction.show_markdown_report("ROP Gadget 4", self.get_rop_report(
                self.state_history[hex(self.gadget4)], registers[self.bv.arch.name], self.gadget4))
            interaction.show_markdown_report("ROP Gadget 5", self.get_rop_report(
                found, registers[self.bv.arch.name], found.solver.eval(found.regs.pc, cast_to=int)))
            self.state_history[hex(self.gadget5)] = found

            sortedDict = collections.OrderedDict(sorted(self.payload.items()))
            print("Payload", sortedDict)
            interaction.show_markdown_report(
                'ROP Stack', self.get_stack_report(sortedDict))
            # BackgroundTaskManager.set_exploit_payload(self.init, sortedDict)
            BackgroundTaskManager.exploit_to_json(self.bv, self.init, sortedDict)


class FileExploitCreator(Explorer):
    def __init__(self, bv, init, payload):
        self.bv = bv
        self.init = init
        self.payload = payload

    def explore(self):
        pass

    def generate_exploit(self, payload):
        exploit = self.init
        for key, value in payload.items():
            exploit += value
        return exploit

    def run(self):
        exploit = self.generate_exploit(self.payload)
        prompt_file = get_save_filename_input('filename')
        if(not prompt_file):
            return
        print("exploit", exploit)
        file_exploit = open(prompt_file, 'wb')
        file_exploit.write(exploit)
        file_exploit.close()
        show_message_box("Exploit Creator", "Exploit saved to file",
                         MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.InformationIcon)


class JSONExploitCreator(Explorer):
    def __init__(self, bv, init, payload):
        self.bv = bv
        self.init = init
        self.payload = payload

    def explore(self):
        pass

    def decode_from_bytes(self, data):
        binja.log_info("DATA IS {0}".format(data))
        decoded_dict = collections.OrderedDict()
        for k, v in data.items():
            decoded_dict[k.decode()] = u32(v)
        return decoded_dict

    def run(self):
        ordered_dict = self.decode_from_bytes(self.payload)
        ordered_dict['junk'] = binascii.hexlify(self.init[0:164]).decode()
        ordered_dict['second'] = u32(self.init[164:168])
        ordered_dict['first'] = u32(self.init[168:172])
        # self.payload['init']=self.init
        data = json.dumps(ordered_dict, ensure_ascii=False, indent=4)
        prompt_file = get_save_filename_input('filename', 'json')
        if(not prompt_file):
            return
        output_file = open(prompt_file.decode("utf-8")+'.json', 'w')
        output_file.write(data)
        output_file.close()
        show_message_box("Exploit Creator", "Exploit saved as JSON",
                         MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.InformationIcon)

ui_plugin = UIPlugin()
btm = BackgroundTaskManager()

PluginCommand.register(
    "AngrExplorer\\5. Explore", "Attempt to solve for a path that satisfies the constraints given", btm.vuln_explore)
# PluginCommand.register("AngrExplorer\ROP\Build",
                       # "Try to build exploit rop chain", btm.build_rop)
# PluginCommand.register("Explorer\WR941ND\Generate Exploit\Save as JSON",
#                        "Try to save exploit as JSON", btm.exploit_to_json)
# PluginCommand.register("Explorer\WR941ND\Generate Exploit\Save to File",
#                        "Try to build exploit fom rop chain", btm.exploit_to_file)

PluginCommand.register_for_address("AngrExplorer\\0. Start Address - Set",
                                                   "Set execution starting point address", ui_plugin.set_start_address)
PluginCommand.register("AngrExplorer\\1. Start Address - Clear",
                                "Clear starting point address", ui_plugin.clear_start_address)
PluginCommand.register_for_address(
    "AngrExplorer\\2. End Address - Set", "Set execution end address", ui_plugin.set_end_address)
PluginCommand.register("AngrExplorer\\2. End Address - Clear",
                                "Clear end point address", ui_plugin.clear_end_address)
# PluginCommand.register("AngrExplorer\ROP\Shared Library\Select",
                                # "Try to build exploit rop chain", ui_plugin.choice_menu)
PluginCommand.register(
    "AngrExplorer\\3. Set Library Path", "Add LD_PATH", ui_plugin.set_ld_path)
PluginCommand.register_for_function(
    "AngrExplorer\\4. Function - Set Params", "Add function params", ui_plugin.set_function_params)
PluginCommand.register_for_function(
    "AngrExplorer\\4. Function - Find Param Origin", "Find origin of function param", ui_plugin.find_arg_origin)
PluginCommand.register(
        "AngrExplorer\\9. Clear All", "Clear data", ui_plugin.clear)
