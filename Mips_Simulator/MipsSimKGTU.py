# GROUP MEMBERS
# 192010020035 - İlkay Türe
# 192010020011 - Furkan Ali Tunç
# 192010020100 - Hatice Betül Eseroğlu

# The working video of the first phase of the project is in the file.

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import sys
import re

class App:
    def save_file(self):
        file_path = filedialog.asksaveasfilename(filetypes=[("Text Files", "*.asm"), ("All Files", "*.*")])
        if file_path:
            with open(file_path, "w") as file:
                pass

    def open_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.asm"), ("All Files", "*.*")])
        if file_path:
            with open(file_path, "r") as file:
                content = file.read()


    def show_about(self):
        messagebox.showinfo("About", "This is a mips simulator. This program was made by FURKAN ALİ TUNÇ, İLKAY TÜRE and HATİCE BETÜL ESEROĞLU. ")
    def cut_text(self):
        selected_text = self.text_widget.selection_get()
        self.text_widget.delete("sel.first", "sel.last")
        self.window.clipboard_clear()
        self.window.clipboard_append(selected_text)

    def copy_text(self):
        selected_text = self.text_widget.selection_get()
        self.window.clipboard_clear()
        self.window.clipboard_append(selected_text)

    def paste_text(self):
       clipboard_text = self.window.clipboard_get()
       self.text_widget.insert("insert", clipboard_text)


    def exit_program(self):
        sys.exit()

    def run_code(self):

        self.output_text.delete("1.0", "end")
        self.reg_text.delete("1.0", "end")
        self.memorytext_text.delete("1.0", "end")

        self.memory = [0] * 1024
        base_address = 0x00400000

        numberLine = 0
        code = self.code_text.get("1.0", "end-1c")

        lines = code.split('\n')

        direction = {}
        for i in range(0,50):
            direction[i] = -1

        register_names = {
            '$zero': 0, '$at': 1, '$v0': 2, '$v1': 3, '$a0': 4, '$a1': 5, '$a2': 6, '$a3': 7,
            '$t0': 8, '$t1': 9, '$t2': 10, '$t3': 11, '$t4': 12, '$t5': 13, '$t6': 14, '$t7': 15,
            '$s0': 16, '$s1': 17, '$s2': 18, '$s3': 19, '$s4': 20, '$s5': 21, '$s6': 22, '$s7': 23,
            '$t8': 24, '$t9': 25, '$k0': 26, '$k1': 27, '$gp': 28, '$sp': 29, '$fp': 30, '$ra': 31,
            'hi': 32, 'lo': 33,
        }

        register_values = {'$zero': 0, '$at': 0, '$v0': 0, '$v1': 0, '$a0': 0, '$a1': 0, '$a2': 0,
                           '$a3': 0, '$t0': 0, '$t1': 0, '$t2': 0, '$t3': 0, '$t4': 0, '$t5': 0,
                           '$t6': 0, '$t7': 0, '$s0': 0, '$s1': 0, '$s2': 0, '$s3': 0, '$s4': 0,
                           '$s5': 0, '$s6': 0, '$s7': 0, '$t8': 0, '$t9': 0, '$k0': 0, '$k1': 0,
                           '$gp': 0, '$sp': 0, '$fp': 0, '$ra': 0, 'hi': 0, 'lo': 0, }

        opcode_to_binary = {
            'add' : '00000',
            'sub' : '00001',
            'and' : '00010',
            'or'  : '00011',
            'xor' : '00100',
            'sll' : '00101',
            'srl' : '00110',
            'jr'  : '00111',
            'j'   : '01001',
            'jal' : '01010',
            'lw'  : '01011',
            'sw'  : '01100',
            'addi': '01101',
            'andi': '01110',
            'ori' : '01111',
            'bne' : '10000',
            'beq' : '10001',
           
        }

        # funct_to_binary = {
        #     'add': '00000',
        #     'sub': '00001',
        #     'and': '00010',
        #     'or':  '00011',
        #     'xor': '00100',
        #     'sll': '00101',
        #     'srl': '00110',
        #     'jr':  '00111',
        #     'mult': '011000',
        #     'div': '011010',
        #     'mfhi': '010000',
        #     'mflo': '010010',
        # }

        def get_hex_number(registers):
            return 0x00000000

        def binary_to_hex(binary):
            return hex(int(binary, 2)).zfill(8)

        def get_imm_value(imm):

            base = 10
            if imm.startswith("0x"):
                base = 16
                imm = imm[2:]
            elif imm.startswith("0b"):
                base = 2
                imm = imm[2:]

            return int(imm, base)

        def format_hex(hex_num):
            hex_str = hex(hex_num)[2:]

            hex_str = hex_str.rjust(8, '0')

            hex_str = '0x' + hex_str

            return hex_str

        def twos_complement(n):

            binary = format(n & 0xffffffff, '032b')

            twos_comp = ''.join(['1' if bit == '0' else '0' for bit in binary])

            twos_comp = format(int(twos_comp, 2) + 1, '032b')

            result = int(twos_comp, 2)

            return result

        def get_label_offset(label, current_address, label_offsets):
            if label in label_offsets:
                label_address = label_offsets[label]
                offset = (label_address - current_address) // 4
                return offset
            else:
                label_offsets[label] = current_address
                return None


        def get_imm_value_lui(imm_string, signed=True):

            negative = imm_string[0] == '-'

            imm_value = int(imm_string, 0)

            if signed and negative:
                imm_value = twos_complement(imm_value, len(imm_string) * 4)

            return imm_value

        MEMORY_SIZE = 1024
        memory = [0] * MEMORY_SIZE

        memory_values={}
        memory_byte_values={}

        def write_memory(address, data):
            # if address < 0 or address >= MEMORY_SIZE:
            #     raise ValueError(f"Memory access error: address out of bounds ({address})")
            memory_values[hex(address)] = format_hex(data)
            #memory[address] = data & 0xFF

        def read_memory(address):
            # if address < 0 or address >= MEMORY_SIZE:
            #     raise ValueError(f"Memory access error: address out of bounds ({address})")
            valueee = memory_values[hex(address)]
            return value
        
        def write_memory_byte(address, data):
            # if address < 0 or address >= MEMORY_SIZE:
            #     raise ValueError(f"Memory access error: address out of bounds ({address})")
            memory_byte_values[hex(address)] = data

        def read_memory_byte(address):
            # if address < 0 or address >= MEMORY_SIZE:
            #     raise ValueError(f"Memory access error: address out of bounds ({address})")
            valuee = memory_byte_values[hex(address)]
            return valuee

        def get_imm_value_lw(imm_str):
            imm_str = imm_str.strip("()")

            if imm_str.startswith("0x") or imm_str.startswith("0X"):

                return int(imm_str, 16)
            else:

                return int(imm_str)

        for line in lines:

            #   for j
            # for i, line in enumerate(lines):
            #     if line.startswith("j"):
            #         label = line.split()[1]  # "j etiket" --> ["j", "etiket"] --> "etiket"
            #         for j, line2 in enumerate(lines[i+1:]):  # etiketin hemen altındaki kodlara kadar ilerle
            #             if line2.startswith(label + ":"):
            #                 print("BULUNDU")
            #                 break
            #         else:
            #             print("BULUNAMADI")
            #             raise ValueError(f"Etiket '{label}' bulunamadı!")

            line = line.strip()

            if not line or line.startswith("#") or line.startswith(".") or line.endswith(":"):
                continue

            words = re.findall(r'\$?\w+', line)
            #print(words)

            instruction = words[0]
            args = words[1:]

            while words:
                if instruction == 'add':

                    rd = register_names[args[0]]
                    rs = register_names[args[1]]
                    rt = register_names[args[2]]

                    opcode = opcode_to_binary[instruction]
                    funct = funct_to_binary[instruction]

                    binary = f'{opcode}{rs:03b}{rt:03b}{rd:03b}00'

                    hexcode = binary_to_hex(binary)

                    self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n ")
                    register_values[args[0]] = register_values[args[1]] + register_values[args[2]]
                    #self.reg_text.insert("end", f"Name:{args[0]}---Number:{rd}----Value:{format_hex(register_values[args[0]])} \n") # = /**Eklenenİlk: {register_values[args[1]]}  + Eklenen2:  {imm}*//

                    numberLine += 1
                    base_address += 4

                    # del words[:4]
                    words = words[4:]
                    #print(words)

                elif instruction == 'sub':
                    rd = register_names[args[0]]
                    rs = register_names[args[1]]
                    rt = register_names[args[2]]

                    opcode = opcode_to_binary[instruction]
                    funct = funct_to_binary[instruction]

                    binary = f'{opcode}{rs:03b}{rt:03b}{rd:03b}00'

                    hexcode = binary_to_hex(binary)

                    self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n ")
                    if(register_values[args[2]] > register_values[args[1]]):
                        register_values[args[0]] = register_values[args[1]] - register_values[args[2]]  #-4

                        #register_values[args[0]] = twos_complement(register_values[args[0]])
                        #print(register_values[args[0]])
                        #print(hex(twos_complement(register_values[args[0]])))
                        #self.reg_text.insert("end", f"Name:{args[0]}---Number:{rd}----Value:{twos_complement(register_values[args[0]])} \n") # = /**Eklenenİlk: {register_values[args[1]]}  + Eklenen2:  {imm}*//

                    else:
                        register_values[args[0]] = register_values[args[1]] - register_values[args[2]]
                        #self.reg_text.insert("end", f"Name:{args[0]}---Number:{rd}----Value:{format_hex(register_values[args[0]])} \n") # = /**Eklenenİlk: {register_values[args[1]]}  + Eklenen2:  {imm}*//

                    numberLine += 1
                    base_address += 4

                    # del words[:4]
                    words = words[4:]
                    #print(words)

                elif instruction == 'and':
                    rd = register_names[args[0]]
                    rs = register_names[args[1]]
                    rt = register_names[args[2]]

                    opcode = opcode_to_binary[instruction]
                    funct = funct_to_binary[instruction]

                    binary = f'{opcode}{rs:03b}{rt:03b}{rd:03b}00'

                    hexcode = binary_to_hex(binary)

                    # direction[numberLine] = None
                    # print("and none")

                    self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")
                    register_values[args[0]] = register_values[args[1]] & register_values[args[2]]
                    #self.reg_text.insert("end", f"Name:{args[0]}---Number:{rd}----Value:{format_hex(register_values[args[0]])} \n")

                    base_address += 4
                    numberLine += 1

                    # del words[:4]
                    words = words[4:]
                    #print(words)

                elif instruction == 'or':
                    rd = register_names[args[0]]
                    rs = register_names[args[1]]
                    rt = register_names[args[2]]

                    opcode = opcode_to_binary[instruction]
                    funct = funct_to_binary[instruction]

                    binary = f'{opcode}{rs:03b}{rt:03b}{rd:03b}00'

                    hexcode = binary_to_hex(binary)

                    self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")
                    register_values[args[0]] = register_values[args[1]] | register_values[args[2]]
                    # self.reg_text.insert("end", f"Name:{args[0]}---Number:{rd}----Value:{format_hex(register_values[args[0]])} \n")

                    base_address += 4
                    numberLine += 1

                    # del words[:4]
                    words = words[4:]
                    #print(words)

                elif instruction == 'addi':
                    rt = register_names[args[0]]
                    rs = register_names[args[1]]
                    imm = get_imm_value(args[2])
                    #print(args[0])

                    opcode = opcode_to_binary[instruction]

                    binary = f'{opcode}{rs:03b}{rt:03b}{imm:05b}'
                    hexcode = binary_to_hex(binary)

                    # direction[numberLine] = None
                    # print("AddiNone")

                    self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")
                    register_values[args[0]] = register_values[args[1]] + imm
                    # self.reg_text.insert("end", f"Name:{args[0]}---Number:{rt}----Value:{format_hex(register_values[args[0]])} \n") # = /**Eklenenİlk: {register_values[args[1]]}  + Eklenen2:  {imm}*//

                    base_address += 4
                    numberLine += 1

                    # del words[:4]
                    words = words[4:]
                    #print(words)

                elif instruction == 'andi':
                    rt = register_names[args[0]]
                    rs = register_names[args[1]]
                    imm = get_imm_value(args[2])

                    opcode = opcode_to_binary[instruction]

                    binary = f'{opcode}{rs:03b}{rt:03b}{imm:05b}'

                    hexcode = binary_to_hex(binary)

                    self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")
                    register_values[args[0]] = register_values[args[1]] & imm
                    # self.reg_text.insert("end", f"Name:{args[0]}---Number:{rt}----Value:{format_hex(register_values[args[0]])} \n")

                    base_address += 4
                    numberLine += 1

                    # del words[:4]
                    words = words[4:]
                    #print(words)

                elif instruction == 'ori':
                    rt = register_names[args[0]]
                    rs = register_names[args[1]]
                    imm = get_imm_value(args[2])

                    opcode = opcode_to_binary[instruction]

                    binary = f'{opcode}{rs:03b}{rt:03b}{imm:05b}'

                    hexcode = binary_to_hex(binary)

                    self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")
                    register_values[args[0]] = register_values[args[1]] | imm
                    # self.reg_text.insert("end", f"Name:{args[0]}---Number:{rt}----Value:{format_hex(register_values[args[0]])} \n")

                    base_address += 4
                    numberLine += 1

                    # del words[:4]
                    words = words[4:]
                    #print(words)

                elif instruction == 'xor':
                    rd = register_names[args[0]]
                    rs = register_names[args[1]]
                    rt = register_names[args[2]]

                    opcode = opcode_to_binary[instruction]
                    funct = funct_to_binary[instruction]

                    binary = f'{opcode}{rs:03b}{rt:03b}{rd:03b}00'

                    hexcode = binary_to_hex(binary)

                    self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")
                    register_values[args[0]] = register_values[args[1]] ^ register_values[args[2]]
                    # self.reg_text.insert("end", f"Name:{args[0]}---Number:{rd}----Value:{format_hex(register_values[args[0]])} \n")

                    base_address += 4
                    numberLine += 1

                    # del words[:4]
                    words = words[4:]
                    #print(words)

                
                # shift left logical
                elif instruction == 'sll':
                    rd = register_names[args[0]]
                    rt = register_names[args[1]]
                    shamt = int(args[2])

                    opcode = opcode_to_binary[instruction]
                    funct = funct_to_binary[instruction]

                    binary = f'{opcode}00000{rt:03b}{rd:03b}{shamt:02b}'

                    hexcode = binary_to_hex(binary)

                    self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")

                    register_values[args[0]] = register_values[args[1]] << shamt

                    # self.reg_text.insert("end", f"Name:{args[0]}---Number:{rd}----Value:{format_hex(register_values[args[0]])} \n")

                    base_address += 4
                    numberLine += 1

                    # del words[:4]
                    words = words[4:]

                elif instruction == 'srl':
                    rd = register_names[args[0]]
                    rt = register_names[args[1]]
                    shamt = int(args[2])

                    opcode = opcode_to_binary[instruction]
                    funct = funct_to_binary[instruction]

                    binary = f'{opcode}000{rt:03b}{rd:03b}{shamt:02b}'

                    hexcode = binary_to_hex(binary)

                    self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")

                    register_values[args[0]] = register_values[args[1]] >> shamt

                    # self.reg_text.insert("end", f"Name:{args[0]}---Number:{rd}----Value:{format_hex(register_values[args[0]])} \n")

                    base_address += 4
                    numberLine += 1

                    # del words[:4]
                    words = words[4:]


                elif instruction == 'jr':
                    rs = register_names[args[0]]

                    target_line_number = -1
                    for i, line in enumerate(lines):
                        if line.startswith('jal'):
                            target_line_number = i
                            break

                    if target_line_number == -1:
                        raise ValueError(f"Label 'JAL' not found")

                    pc = target_line_number * 4
                    target_address = 0x00400000 + pc
                    numberLine-=2

                    direction[numberLine] = target_line_number

                    opcode = opcode_to_binary[instruction]
                    binary = f'{opcode}{rs:05b}000000000000000{funct_to_binary[instruction]}'
                    hexcode = binary_to_hex(binary)
                    self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: jr $ra        Jump: {hex(target_address)}\n")
                    #pc = register_values[args[0]]

                    #base_address = pc
                    #self.reg_text.insert("end", f"JR--UPDATE Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")

                    # del words[:4]
                    base_address += 4
                    numberLine += 1
                    words = words[4:]
                    #print(direction)


        

                elif instruction == 'lw':
                    rt = register_names[args[0]]
                    offset = get_imm_value_lw(args[1])

                    opcode = opcode_to_binary[instruction]

                    binary = f'{opcode}{register_names[args[2]]:05b}{rt:05b}{offset:016b}'

                    hexcode = binary_to_hex(binary)

                    self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")

                    # address = register_values[args[2]] + offset
                    # data = read_memory(address)
                    # register_values[args[0]] = data
                    # self.reg_text.insert("end", f"Name:{args[0]}---Number:{rt}----Value:{format_hex(register_values[args[0]])} \n")

                    # formatted_address = format(address, '08x')
                    # formatted_data = format(data, '08x')
                    # self.output_text.insert("end", f"Accessed Memory: Address: 0x{formatted_address}        Data: 0x{formatted_data}\n")
                    
                    base_address += 4
                    numberLine += 1

                    # del words[:4]
                    words = words[4:]
                    #print(words)

                elif instruction == 'sw':
                    rt = register_names[args[0]]
                    offset = get_imm_value(args[1])

                    opcode = opcode_to_binary[instruction]
                    binary = f'{opcode}{register_names[args[2]]:05b}{rt:05b}{offset:016b}'

                    hexcode = binary_to_hex(binary)

                    self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")

                    # address = register_values[args[2]] + offset
                    # data = register_values[args[0]]
                    # write_memory(address, data)
                    #self.memorytext_text.insert("end", f"Accessed Memory: Address: {format_hex(address)}        Data: {format_hex(data)}\n")
                    # self.output_text.insert("end", f"Accessed Memory: Address: 0x{formatted_address}        Data: 0x{formatted_data}\n")

                    base_address += 4
                    numberLine += 1
                    words = words[4:]

                elif instruction == 'beq':
                    rs = args[0]
                    rt = args[1]
                    label = args[2]

                    target_line_number = -1
                    for i, line in enumerate(lines):
                        if line.startswith(label + ':'):
                            target_line_number = i
                            break

                    if target_line_number == -1:
                        raise ValueError(f"Label '{label}' not found")

                    pc = target_line_number * 4
                    if(target_line_number>numberLine):
                        pc_beq= (target_line_number-numberLine)-1
                    else:
                        pc_beq= (numberLine-target_line_number)-1
                    target_address = 0x00400000 + pc

                    if(register_values[rs]==register_values[rt]):
                        direction[numberLine] = target_line_number

                    rs = register_names[args[0]]
                    rt = register_names[args[1]]
                    opcode = opcode_to_binary[instruction]
                    binary = f'{opcode}{rs:03b}{rt:03b}{pc_beq:05b}'
                    hexcode = binary_to_hex(binary)
                    self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")
                    base_address += 4
                    numberLine += 1
                    words = []
                    continue

                elif instruction == 'bne':
                    rs = args[0]
                    rt = args[1]
                    label = args[2]

                    #print(register_values[rs])
                    #print(register_values[rt])

                    target_line_number = -1
                    for i, line in enumerate(lines):
                        if line.startswith(label + ':'):
                            target_line_number = i
                            break

                    if target_line_number == -1:
                        raise ValueError(f"Label '{label}' not found")

                    pc = target_line_number * 4
                    if(target_line_number>numberLine):
                        pc_bne= (target_line_number-numberLine)-1
                    else:
                        pc_bne= (numberLine-target_line_number)-1
                    target_address = 0x00400000 + pc

                    if(register_values[rs]!=register_values[rt]):
                        direction[numberLine] = target_line_number

                    rs = register_names[args[0]]
                    rt = register_names[args[1]]
                    opcode = opcode_to_binary[instruction]
                    binary = f'{opcode}{rs:03b}{rt:03b}{pc_bne:05b}'
                    hexcode = binary_to_hex(binary)

                    self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}        Jump: {hex(target_address)}\n")
                    base_address += 4
                    numberLine += 1
                    words = []
                    continue

                elif instruction == 'jal':
                    label = args[0]

                    target_line_number = -1
                    for i, line in enumerate(lines):
                        if line.startswith(label + ':'):
                            target_line_number = i
                            break

                    if target_line_number == -1:
                        raise ValueError(f"Label '{label}' not found")

                    pc = target_line_number * 4
                    pc_jal = target_line_number * 1
                    target_address = 0x00400000 + pc

                    direction[numberLine] = target_line_number

                    #print(direction)
                    opcode = opcode_to_binary[instruction]
                    binary = f'{opcode}{pc_jal:026b}'
                    hexcode = binary_to_hex(binary)
                    self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}        Jump: {hex(target_address)}\n")
                    base_address += 4
                    numberLine += 1
                    words = []
                    continue

                
                elif instruction == 'j':
                    label = args[0]

                    target_line_number = -1
                    for i, line in enumerate(lines):
                        if line.startswith(label + ':'):
                            target_line_number = i
                            break

                    if target_line_number == -1:
                        raise ValueError(f"Label '{label}' not found")

                    pc = target_line_number * 4
                    pc_j = target_line_number * 1
                    target_address = 0x00400000 + pc

                    direction[numberLine] = target_line_number
                    #print(f"Target Line Number: {target_line_number}")
                    #print(direction)

                    #print(direction)
                    opcode = opcode_to_binary[instruction]
                    binary = f'{opcode}{pc_j:011b}'
                    hexcode = binary_to_hex(binary)
                    self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}        Jump: {hex(target_address)}\n")
                    base_address += 4
                    numberLine += 1
                    words = []
                    continue
        
        #print("Part2")
        #print(f"Direction:  {direction}")
        self.output_text.insert("end",f"******************************************** \n")
        self.reg_text.insert("end",f"******************************************** \n")
        self.memorytext_text.insert("end",f"******************************************** \n")
        base_address = 0x00400000
        exit=0
        pass_dict={}
        for i in range(0,100):
            pass_dict[i] = 1

        #print(loop_pass)
            #print(pass_dict)
            # for k in pass_dict:
            #     if pass_dict[k] == 0:
            #         #print(f"Beni pass: {k}")

            # if pass_dict[k] == 0:
            #     k+=1

        register_values = {'$zero': 0, '$at': 0, '$v0': 0, '$v1': 0, '$a0': 0, '$a1': 0, '$a2': 0,
                           '$a3': 0, '$t0': 0, '$t1': 0, '$t2': 0, '$t3': 0, '$t4': 0, '$t5': 0,
                           '$t6': 0, '$t7': 0, '$s0': 0, '$s1': 0, '$s2': 0, '$s3': 0, '$s4': 0,
                           '$s5': 0, '$s6': 0, '$s7': 0, '$t8': 0, '$t9': 0, '$k0': 0, '$k1': 0,
                           '$gp': 0, '$sp': 0, '$fp': 0, '$ra': 0, 'hi': 0, 'lo': 0, }

        #for n in enumerate(lines):
            #print(lines[1])
            #print(lines[5])

        #lines var
        current_line = -1
        k=-1
        #for k, line in enumerate(lines):
            #print(lines[k])
        #print(direction)
        #print(lines)

        while current_line < (len(lines)-1):

            current_line+=1
            k+=1
            #print("geçtik")
            line = lines[current_line]

            if exit==1:
                continue
            # if pass_dict[k] == 0:
            #     continue
            #print(f"Line {k}:")
            #print(pass_dict)
            #current_line = lines[k]

            print(lines[current_line])
            # for k in direction:
            #     if direction[k]:
            #         current_line = direction[k]
            #         continue
                    #print(f"{k} -> {direction[k]}")
                    # if(k < direction[k]):
                    #     loop_pass = k+1
                    #     for loop_pass in range(loop_pass, direction[k]):
                    #         pass_dict[loop_pass] = 0
                    # else:
                    #     target = direction[k]
                    #     lines = lines[target: ]

            if not line or line.startswith("#")  or line.endswith(":"):
                continue

            # print(pass_dict)
            if pass_dict[k] != 0:
                # print("not passed")
                line = line.strip()
                words = re.findall(r'\$?\w+', line)
                #print(words)

                instruction = words[0]
                args = words[1:]

                while words:
                    if instruction == ' ' :
                        continue
                    elif instruction == 'beq':
                        rs = args[0]
                        rt = args[1]
                        label = args[2]

                        #print(register_values[rs])
                        #print(register_values[rt])

                        if(register_values[rs]==register_values[rt]):
                            rs = register_names[args[0]]
                            rt = register_names[args[1]]

                            target_line_number = -1
                            for i, line in enumerate(lines):
                                if line.startswith(label + ':'):
                                    target_line_number = i
                                    break

                            if target_line_number == -1:
                                raise ValueError(f"Label '{label}' not found")

                            pc = target_line_number * 4
                            target_address = 0x00400000 + pc

                            direction[numberLine] = target_line_number

                            opcode = opcode_to_binary[instruction]
                            binary = f'{opcode}{rs:05b}{rt:05b}{pc:016b}'
                            hexcode = binary_to_hex(binary)
                            #self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}      Jump: {hex(target_address)}\n")
                        base_address += 4
                        numberLine += 1
                        words = []
                        continue

                    elif instruction == 'bne':
                        rs = args[0]
                        rt = args[1]
                        label = args[2]

                        #print(register_values[rs])
                        #print(register_values[rt])

                        if(register_values[rs]!=register_values[rt]):
                            rs = register_names[args[0]]
                            rt = register_names[args[1]]

                            target_line_number = -1
                            for i, line in enumerate(lines):
                                if line.startswith(label + ':'):
                                    target_line_number = i
                                    break

                            if target_line_number == -1:
                                raise ValueError(f"Label '{label}' not found")

                            pc = target_line_number * 4
                            target_address = 0x00400000 + pc

                            direction[numberLine] = target_line_number

                            opcode = opcode_to_binary[instruction]
                            binary = f'{opcode}{rs:05b}{rt:05b}{pc:016b}'
                            hexcode = binary_to_hex(binary)
                            #self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}      Jump: {hex(target_address)}\n")
                        base_address += 4
                        numberLine += 1
                        words = []
                        continue

                    elif instruction == 'add':
                        rd = register_names[args[0]]
                        rs = register_names[args[1]]
                        rt = register_names[args[2]]
                        opcode = opcode_to_binary[instruction]
                        funct = funct_to_binary[instruction]
                        binary = f'{opcode}{rs:05b}{rt:05b}{rd:05b}00000{funct}'
                        hexcode = binary_to_hex(binary)
                        register_values[args[0]] = register_values[args[1]] + register_values[args[2]]

                        self.reg_text.insert("end", f"Name:{args[0]}---Number:{rd}----Value:{format_hex(register_values[args[0]])} \n") # = /**Eklenenİlk: {register_values[args[1]]}  + Eklenen2:  {imm}*//


                        base_address += 4
                        words = words[4:]
                            #print(words)

                    elif instruction == 'sub':
                        rd = register_names[args[0]]
                        rs = register_names[args[1]]
                        rt = register_names[args[2]]

                        opcode = opcode_to_binary[instruction]
                        funct = funct_to_binary[instruction]

                        binary = f'{opcode}{rs:05b}{rt:05b}{rd:05b}00000{funct}'

                        hexcode = binary_to_hex(binary)

                        #self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")

                        if(register_values[args[2]] > register_values[args[1]]):

                            register_values[args[0]] = register_values[args[1]] - register_values[args[2]]  #-4

                            #register_values[args[0]] = twos_complement(register_values[args[0]])
                            #print(register_values[args[0]])
                            #print(hex(twos_complement(register_values[args[0]])))
                            self.reg_text.insert("end", f"Name:{args[0]}---Number:{rd}----Value:{twos_complement(register_values[args[0]])} \n") # = /**Eklenenİlk: {register_values[args[1]]}  + Eklenen2:  {imm}*//

                        else:
                            register_values[args[0]] = register_values[args[1]] - register_values[args[2]]
                            self.reg_text.insert("end", f"Name:{args[0]}---Number:{rd}----Value:{format_hex(register_values[args[0]])} \n") # = /**Eklenenİlk: {register_values[args[1]]}  + Eklenen2:  {imm}*//

                        base_address += 4

                        # del words[:4]
                        words = words[4:]
                        #print(words)

                    elif instruction == 'and':
                        rd = register_names[args[0]]
                        rs = register_names[args[1]]
                        rt = register_names[args[2]]

                        opcode = opcode_to_binary[instruction]
                        funct = funct_to_binary[instruction]

                        binary = f'{opcode}{rs:05b}{rt:05b}{rd:05b}00000{funct}'

                        hexcode = binary_to_hex(binary)
                        #self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")
                        register_values[args[0]] = register_values[args[1]] & register_values[args[2]]
                        self.reg_text.insert("end", f"Name:{args[0]}---Number:{rd}----Value:{format_hex(register_values[args[0]])} \n")

                        base_address += 4

                        # del words[:4]
                        words = words[4:]
                        #print(words)

                    elif instruction == 'or':
                        rd = register_names[args[0]]
                        rs = register_names[args[1]]
                        rt = register_names[args[2]]
                        opcode = opcode_to_binary[instruction]
                        funct = funct_to_binary[instruction]

                        binary = f'{opcode}{rs:05b}{rt:05b}{rd:05b}00000{funct}'

                        hexcode = binary_to_hex(binary)

                        register_values[args[0]] = register_values[args[1]] | register_values[args[2]]
                        self.reg_text.insert("end", f"Name:{args[0]}---Number:{rd}----Value:{format_hex(register_values[args[0]])} \n")

                        base_address += 4

                        # del words[:4]
                        words = words[4:]
                        #print(words)

                    elif instruction == 'slt':
                        rd = register_names[args[0]]
                        rs = register_names[args[1]]
                        rt = register_names[args[2]]

                        opcode = opcode_to_binary[instruction]
                        funct = funct_to_binary[instruction]

                        binary = f'{opcode}{rs:05b}{rt:05b}{rd:05b}00000{funct}'

                        hexcode = binary_to_hex(binary)

                        #self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")
                        if register_values[args[1]] < register_values[args[2]]:
                            register_values[args[0]] = 1
                        else:
                            register_values[args[0]] = 0
                        self.reg_text.insert("end", f"Name:{args[0]}---Number:{rd}----Value:{format_hex(register_values[args[0]])} \n")

                        base_address += 4

                        # del words[:4]
                        words = words[4:]
                        #print(words)

                    elif instruction == 'addi':
                        rt = register_names[args[0]]
                        rs = register_names[args[1]]
                        imm = get_imm_value(args[2])
                        #print(args[0])

                        opcode = opcode_to_binary[instruction]

                        binary = f'{opcode}{rs:05b}{rt:05b}{imm:016b}'
                        hexcode = binary_to_hex(binary)

                        #self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")
                        register_values[args[0]] = register_values[args[1]] + imm
                        self.reg_text.insert("end", f"Name:{args[0]}---Number:{rt}----Value:{format_hex(register_values[args[0]])} \n") # = /**Eklenenİlk: {register_values[args[1]]}  + Eklenen2:  {imm}*//

                        base_address += 4

                        # del words[:4]
                        words = words[4:]
                        #print(words)

                    elif instruction == 'andi':
                        rt = register_names[args[0]]
                        rs = register_names[args[1]]
                        imm = get_imm_value(args[2])

                        opcode = opcode_to_binary[instruction]

                        binary = f'{opcode}{rs:05b}{rt:05b}{imm:016b}'

                        hexcode = binary_to_hex(binary)

                        #self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")
                        register_values[args[0]] = register_values[args[1]] & imm
                        self.reg_text.insert("end", f"Name:{args[0]}---Number:{rt}----Value:{format_hex(register_values[args[0]])} \n")

                        base_address += 4

                        # del words[:4]
                        words = words[4:]
                        #print(words)

                    elif instruction == 'ori':
                        rt = register_names[args[0]]
                        rs = register_names[args[1]]
                        imm = get_imm_value(args[2])

                        opcode = opcode_to_binary[instruction]

                        binary = f'{opcode}{rs:05b}{rt:05b}{imm:016b}'

                        hexcode = binary_to_hex(binary)

                        #self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")
                        register_values[args[0]] = register_values[args[1]] | imm
                        self.reg_text.insert("end", f"Name:{args[0]}---Number:{rt}----Value:{format_hex(register_values[args[0]])} \n")

                        base_address += 4

                        # del words[:4]
                        words = words[4:]
                        #print(words)

                    elif instruction == 'xor':

                        rd = register_names[args[0]]
                        rs = register_names[args[1]]
                        rt = register_names[args[2]]

                        opcode = opcode_to_binary[instruction]
                        funct = funct_to_binary[instruction]

                        binary = f'{opcode}{rs:05b}{rt:05b}{rd:05b}00000{funct}'

                        hexcode = binary_to_hex(binary)

                        #self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")
                        register_values[args[0]] = register_values[args[1]] ^ register_values[args[2]]
                        self.reg_text.insert("end", f"Name:{args[0]}---Number:{rd}----Value:{format_hex(register_values[args[0]])} \n")

                        base_address += 4

                        # del words[:4]
                        words = words[4:]
                        #print(words)

                    elif instruction == 'slti':
                        rt = register_names[args[0]]
                        rs = register_names[args[1]]
                        imm = get_imm_value(args[2])

                        opcode = opcode_to_binary[instruction]

                        binary = f'{opcode}{rs:05b}{rt:05b}{imm:016b}'

                        hexcode = binary_to_hex(binary)

                        # self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")
                        if register_values[args[1]] < imm:
                            register_values[args[0]] = 1
                        else:
                            register_values[args[0]] = 0
                        self.reg_text.insert("end", f"Name:{args[0]}---Number:{rt}----Value:{format_hex(register_values[args[0]])} \n")

                        base_address += 4

                        # del words[:4]
                        words = words[4:]

                    elif instruction == 'sll':
                        rd = register_names[args[0]]
                        rt = register_names[args[1]]
                        shamt = int(args[2])

                        opcode = opcode_to_binary[instruction]
                        funct = funct_to_binary[instruction]

                        binary = f'{opcode}00000{rt:05b}{rd:05b}{shamt:05b}{funct}'

                        hexcode = binary_to_hex(binary)

                        #self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")

                        register_values[args[0]] = register_values[args[1]] << shamt

                        self.reg_text.insert("end", f"Name:{args[0]}---Number:{rd}----Value:{format_hex(register_values[args[0]])} \n")

                        base_address += 4

                        # del words[:4]
                        words = words[4:]

                    elif instruction == 'srl':
                        rd = register_names[args[0]]
                        rt = register_names[args[1]]
                        shamt = int(args[2])

                        opcode = opcode_to_binary[instruction]
                        funct = funct_to_binary[instruction]

                        binary = f'{opcode}00000{rt:05b}{rd:05b}{shamt:05b}{funct}'

                        hexcode = binary_to_hex(binary)

                        #self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")

                        register_values[args[0]] = register_values[args[1]] >> shamt

                        self.reg_text.insert("end", f"Name:{args[0]}---Number:{rd}----Value:{format_hex(register_values[args[0]])} \n")

                        base_address += 4

                        # del words[:4]
                        words = words[4:]

                    elif instruction == 'sra':
                        rd = register_names[args[0]]
                        rt = register_names[args[1]]
                        shamt = int(args[2])

                        opcode = opcode_to_binary[instruction]
                        funct = funct_to_binary[instruction]

                        binary = f'{opcode}00000{rt:05b}{rd:05b}{shamt:05b}{funct}'

                        hexcode = binary_to_hex(binary)

                        #self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")
                        if register_values[args[1]] < 0:
                            register_values[args[0]] = (register_values[args[1]] >> shamt) | (0xffffffff << (32 - shamt))
                        else:
                            register_values[args[0]] = register_values[args[1]] >> shamt

                        self.reg_text.insert("end", f"Name:{args[0]}---Number:{rd}----Value:{format_hex(register_values[args[0]])} \n")

                        base_address += 4

                        # del words[:4]
                        words = words[4:]


                    elif instruction == 'jr':
                        rs = register_names[args[0]]


                        opcode = opcode_to_binary[instruction]
                        binary = f'{opcode}{rs:05b}000000000000000{funct_to_binary[instruction]}'
                        hexcode = binary_to_hex(binary)
                        # self.output_text.insert("end", f"JR--Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")
                        #pc = register_values[args[0]]
                        #base_address = pc
                        #self.reg_text.insert("end", f"$8(vaddr): {format_hex(register_values[args[0]])}---$14(epc): {format_hex(register_values[args[0]])}  \n")

                        # del words[:4]
                        base_address += 4
                        words = words[4:]
                        #print(f"JRLine: {line}")
                        #print(f"Direction: {direction}")


                    elif instruction == 'mult':
                        rs = register_names[args[0]]
                        rt = register_names[args[1]]

                        opcode = opcode_to_binary[instruction]
                        funct = funct_to_binary[instruction]

                        binary = f'{opcode}{rs:05b}{rt:05b}0000000000{funct}'

                        hexcode = binary_to_hex(binary)

                        # self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")

                        product = register_values[args[0]] * register_values[args[1]]

                        lower_half = product & 0xffffffff
                        upper_half = (product >> 32) & 0xffffffff

                        register_values['hi'] = upper_half
                        register_values['lo'] = lower_half

                        self.reg_text.insert("end", f"Name:hi----Number:{register_names['hi']}----Value:{format_hex(register_values['hi'])} \n")
                        self.reg_text.insert("end", f"Name:lo----Number:{register_names['lo']}----Value:{format_hex(register_values['lo'])} \n")

                        base_address += 4

                        # del words[:4]
                        words = words[4:]

                    elif instruction == 'div':
                        rs = register_names[args[0]]
                        rt = register_names[args[1]]

                        opcode = opcode_to_binary[instruction]
                        funct = funct_to_binary[instruction]

                        binary = f'{opcode}{rs:05b}{rt:05b}0000000000{funct}'

                        hexcode = binary_to_hex(binary)

                        # self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")

                        dividend = register_values[args[0]]
                        divisor = register_values[args[1]]
                        quotient = dividend // divisor
                        remainder = dividend % divisor

                        register_values['hi'] = remainder
                        register_values['lo'] = quotient

                        self.reg_text.insert("end", f"Name:hi----Number:{register_names['hi']}----Value:{format_hex(register_values['hi'])} \n")
                        self.reg_text.insert("end", f"Name:lo----Number:{register_names['lo']}----Value:{format_hex(register_values['lo'])} \n")

                        base_address += 4

                        # del words[:4]
                        words = words[4:]

                    elif instruction == 'mfhi':

                        rd = register_names[args[0]]

                        opcode = opcode_to_binary[instruction]
                        funct = funct_to_binary[instruction]

                        binary = f'{opcode}0000000000{rd:05b}00000{funct}'

                        hexcode = binary_to_hex(binary)

                        # self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")

                        value = register_values['hi']

                        register_values[args[0]] = value

                        self.reg_text.insert("end", f"Name:{args[0]}---Number:{rd}----Value:{format_hex(value)} \n")

                        base_address += 4

                        # del words[:4]
                        words = words[4:]

                    elif instruction == 'mflo':
                        rd = register_names[args[0]]

                        opcode = opcode_to_binary[instruction]
                        funct = funct_to_binary[instruction]

                        binary = f'{opcode}0000000000{rd:05b}00000{funct}'

                        hexcode = binary_to_hex(binary)

                        # self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")

                        value = register_values['lo']

                        register_values[args[0]] = value

                        self.reg_text.insert("end", f"Name:{args[0]}---Number:{rd}----Value:{format_hex(value)} \n")

                        base_address += 4

                        # del words[:4]
                        words = words[4:]

                    elif instruction == 'lui':
                        rt = register_names[args[0]]
                        imm = get_imm_value_lui(args[1], signed=False)

                        opcode = opcode_to_binary[instruction]

                        binary = f'{opcode}00000{rt:05b}{imm:016b}'

                        hexcode = binary_to_hex(binary)
                        # self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")
                        register_values[args[0]] = imm << 16
                        self.reg_text.insert("end", f"Name:{args[0]}---Number:{rt}----Value:{format_hex(register_values[args[0]])} \n")

                        base_address += 4

                        # del words[:4]
                        words = words[4:]
                        #print(words)

                    elif instruction == 'lw':
                        rt = register_names[args[0]]
                        offset = get_imm_value_lw(args[1])

                        opcode = opcode_to_binary[instruction]

                        binary = f'{opcode}{register_names[args[2]]:05b}{rt:05b}{offset:016b}'

                        hexcode = binary_to_hex(binary)

                        # self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")

                        #print(memory_values)

                        address = register_values[args[2]] + offset

                        data = memory_values[hex(address)]
                        #print(data)

                        register_values[args[0]] = data

                        #self.reg_text.insert("end", f"Accessed Memory: Address: {hex(address)}        Data: {data}\n")

                        self.reg_text.insert("end", f"Name:{args[0]}---Number:{rt}----Value:{data} \n")

                        # formatted_address = format(address, '08x')
                        # formatted_data = format(data, '08x')

                        #self.reg_text.insert("end", f"Name:{args[0]}---Number:{rt}----Value:{format_hex(register_values[args[0]])}----$8(vaddr):0x{formatted_address}----$14(epc):{hex(now_address_lw)}  \n")

                        # self.output_text.insert("end", f"Accessed Memory: Address: 0x{formatted_address}        Data: 0x{formatted_data}\n")

                        base_address += 4
                        # del words[:4]
                        words = words[4:]
                        #print(words)
                    
                    elif instruction == 'lb':
                        rt = register_names[args[0]]
                        offset = get_imm_value(args[1])

                        opcode = opcode_to_binary[instruction]

                        binary = f'{opcode}{register_names[args[2]]:05b}{rt:05b}{offset:016b}'

                        hexcode = binary_to_hex(binary)

                        #now_address_lb = base_address
                        # self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")

                        if offset in range(0,4):
                            address = register_values[args[2]] + 0

                        if offset in range(4,8):
                            address = register_values[args[2]] + 4

                        readed_data = read_memory_byte(address)

                        if offset==0 or offset==4:
                            decimal = int(readed_data[6:], 16)
                            formatted_decimal = format_hex(decimal)
                            register_values[args[0]] = formatted_decimal
                            self.reg_text.insert("end", f"Name:{args[0]}---Number:{rt}----Value: {register_values[args[0]]} \n")

                        elif offset==1 or offset==5:
                            decimal = int(readed_data[4:6], 16)
                            formatted_decimal = format_hex(decimal)
                            register_values[args[0]] = formatted_decimal
                            self.reg_text.insert("end", f"Name:{args[0]}---Number:{rt}----Value: {register_values[args[0]]} \n")

                        elif offset==2 or offset==6:
                            decimal = int(readed_data[2:4], 16)
                            formatted_decimal = format_hex(decimal)
                            register_values[args[0]] = formatted_decimal
                            self.reg_text.insert("end", f"Name:{args[0]}---Number:{rt}----Value: {register_values[args[0]]} \n")

                        elif offset==3 or offset==7:
                            decimal = int(readed_data[0:2], 16)
                            formatted_decimal = format_hex(decimal)
                            register_values[args[0]] = formatted_decimal
                            self.reg_text.insert("end", f"Name:{args[0]}---Number:{rt}----Value: {register_values[args[0]]} \n")
                        

                        base_address += 4
                        words = words[4:]

                        #formatted_address = format(address, '08x')
                        #formatted_data = format(data, '08x')

                        #self.reg_text.insert("end", f"Name:{args[0]}---Number:{rt}----Value:{format_hex(register_values[args[0]])}----$8(vaddr):0x{formatted_address}----$14(epc):{hex(now_address_lb)}  \n")

                        #exit=1
                        # self.output_text.insert("end", f"Accessed Memory: Address: 0x{formatted_address}        Data: 0x{formatted_data}\n")



                    elif instruction == 'sw':
                        rt = register_names[args[0]]
                        offset = get_imm_value(args[1])

                        opcode = opcode_to_binary[instruction]
                        binary = f'{opcode}{register_names[args[2]]:05b}{rt:05b}{offset:016b}'

                        hexcode = binary_to_hex(binary)

                        now_address_sw =base_address

                        # self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")

                        address = register_values[args[2]] + offset
                        data = register_values[args[0]]

                        write_memory(address, data)

                        self.memorytext_text.insert("end", f"Accessed Memory: Address: {format_hex(address)}        Data: {format_hex(data)}\n")

                        #print(memory_values)

                        # formatted_address = format(address, '08x')
                        # formatted_data = format(data, '08x')

                        #self.reg_text.insert("end", f"Name:{args[0]}---Number:{rt}----Value:{format_hex(register_values[args[0]])}----$8(vaddr):0x{formatted_address}----$14(epc):{hex(now_address_sw)}  \n")

                        # self.output_text.insert("end", f"Accessed Memory: Address: 0x{formatted_address}        Data: 0x{formatted_data}\n")
                        base_address += 4
                        words = words[4:]

                    elif instruction == 'sb':
                        rt = register_names[args[0]]
                        offset = get_imm_value(args[1])
                        opcode = opcode_to_binary[instruction]

                        binary = f'{opcode}{register_names[args[2]]:05b}{rt:05b}{offset:016b}'

                        hexcode = binary_to_hex(binary)

                        #now_address_sb = base_address
                        # self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")
                        
                        if offset in range(0,4):
                            address = register_values[args[2]] + 0

                        if offset in range(4,8):
                            address = register_values[args[2]] + 4
                        offset1 = False
                        
                        if offset==0 or offset==4:
                            #print("offset0")
                            data_one = register_values[args[0]]  # Keep only the least significant byte
                            format_data_one = format(data_one, 'x')
                            self.memorytext_text.insert("end", f"Accessed Memory: Address: {format_hex(address)}        Data: 0x000000{format_data_one}\n")
                            write_memory(address, data_one)
                            #print(data_one)
                            #print(memory_values)

                        elif offset==1 or offset==5:
                            #print("offset1")
                            data_two = register_values[args[0]]
                            format_data_two = format(data_two, 'x')
                            self.memorytext_text.insert("end", f"Accessed Memory: Address: {format_hex(address)}        Data: 0x0000{format_data_two}{format_data_one}\n")
                            #datas = (data_two*100) + data_one
                            write_memory(address, data_two)
                            #print(memory_values)

                        elif offset==2 or offset==6:
                            #print("offset2")
                            data_three = register_values[args[0]]  # Keep only the least significant byte
                            format_data_three = format(data_three, 'x')
                            self.memorytext_text.insert("end", f"Accessed Memory: Address: {format_hex(address)}        Data: 0x00{format_data_three}{format_data_two}{format_data_one}\n")
                            write_memory(address, data_three)
                            #print(memory_values)

                        elif offset==3 or offset==7:
                            #print("offset3")
                            data_four = register_values[args[0]]
                            format_data_four = format(data_four, 'x')
                            self.memorytext_text.insert("end", f"Accessed Memory: Address: {format_hex(address)}        Data: 0x{format_data_four}{format_data_three}{format_data_two}{format_data_one}\n")
                            write_memory(address, data_four)
                            #print(memory_values)

                            if offset in range(0,4):
                                address = register_values[args[2]] + 0
                            if offset in range(4,8):
                                address = register_values[args[2]] + 4
                            memory_byte = format_data_four + format_data_three + format_data_two + format_data_one
                            write_memory_byte(address, memory_byte)
                            print(memory_byte_values)

                        base_address += 4
                        words = words[4:]

                        #formatted_address = format(address, '08x')
                        #formatted_data = format(data, '08x')
                        #self.reg_text.insert("end", f"Name:{args[0]}---Number:{rt}----Value:{format_hex(register_values[args[0]])}----$8(vaddr):0x{formatted_address}----$14(epc):{hex(now_address_sb)}  \n")
                        #self.output_text.insert("end",    f"Accessed Memory: Address: 0x{formatted_address}                   Data: 0x{formatted_data}\n")

                        #exit=1


                    elif instruction == 'jal':
                        label = args[0]

                        line_number = -1
                        for i, line in enumerate(lines):
                            if line.startswith(label + ':'):
                                line_number = i
                                break

                        if line_number == -1:
                            raise ValueError(f"Label '{label}' not found")

                        pc = line_number * 1
                        target_address = 0x00400000 + pc

                        opcode = opcode_to_binary[instruction]

                        binary = f'{opcode}{pc:026b}'

                        hexcode = binary_to_hex(binary)
                        ra_address=base_address+4
                        # self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}     Jump: {hex(target_address)}   \n")
                        self.reg_text.insert("end", f"Name:$ra---Number:31----Value:{format_hex(ra_address)}\n")
                        base_address += 4
                        words = []
                        continue

                    elif instruction == 'j':
                        label = args[0]

                        line_number = -1
                        for i, line in enumerate(lines):
                            if line.startswith(label + ':'):
                                line_number = i
                                break

                        if line_number == -1:
                            raise ValueError(f"Label '{label}' not found")

                        pc = line_number * 4
                        target_address = 0x00400000 + pc

                        opcode = opcode_to_binary[instruction]

                        binary = f'{opcode}{pc:026b}'

                        hexcode = binary_to_hex(binary)

                        # self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}     Jump: {hex(target_address)}   \n")
                        base_address += 4
                        words = []
                        continue
                        
            if direction[k] != -1:
                current_line = direction[k]
                print(f"CurrentLine yani siradaki: {current_line}")
                continue
            # current_line+=1
            # k+=1

    def __init__(self):
        self.window = tk.Tk()
        self.window.title("KGTU MIPS Simulator")
        self.window.geometry("1500x800")

        self.menu_bar = tk.Menu(self.window)
        self.window.config(menu=self.menu_bar)
        self.file_menu = tk.Menu(self.menu_bar)
        self.menu_bar.add_cascade(label="File", menu=self.file_menu)
        self.file_menu.add_command(label="Open", command=self.open_file)
        self.file_menu.add_command(label="Save", command=self.save_file)
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Exit", command=self.exit_program)

        self.help_menu = tk.Menu(self.menu_bar)
        self.menu_bar.add_cascade(label="Help", menu=self.help_menu)
        self.help_menu.add_command(label="About", command=self.show_about)

        self.edit_menu = tk.Menu(self.menu_bar)
        self.menu_bar.add_cascade(label="Edit", menu=self.edit_menu)
        self.edit_menu.add_command(label="Cut", command=self.cut_text)
        self.edit_menu.add_command(label="Copy", command=self.copy_text)
        self.edit_menu.add_command(label="Paste", command=self.paste_text)

        self.run_menu = tk.Menu(self.menu_bar)
        self.menu_bar.add_cascade(label="Run", menu=self.run_menu)
        self.run_menu.add_command(label="Run Code", command=self.run_code)

        self.notebook = ttk.Notebook(self.window)
        self.notebook.pack(pady=25)

        self.code_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.code_tab, text="Code")
        self.code_text = tk.Text(self.code_tab, height=1000, width=900)
        self.code_text.pack(padx=25, pady=25)

        self.output_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.output_tab, text="Execute")
        self.output_text = tk.Text(self.output_tab, height=100, width=700)
        self.output_text.pack(padx=25, pady=25)

        self.reg_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.reg_tab, text="Register Name - Number - Value")
        self.reg_text = tk.Text(self.reg_tab, height=100, width=700)
        self.reg_text.pack(padx=25, pady=25)

        self.memory_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.memory_tab, text="Memory")


        data_mem_frame = ttk.Frame(self.memory_tab)
        data_mem_frame.pack(side="left", padx=25, pady=25)
        text_entry_frame = ttk.Frame(data_mem_frame)
        text_entry_frame.pack(side="top", padx=15, pady=15)

        self.memorytext_text = tk.Text(data_mem_frame, height=50, width=900)
        self.memorytext_text.pack(side="top", padx=15, pady=15)

        # data_mem_label.pack()

        # data_mem_table = ttk.Treeview(data_mem_frame, columns=("address", "value +0", "value +4", "value +8", "value +C", "value +10", "value +14", "value +18", "value +1C"), height=12)
        # data_mem_table.heading("#0", text="Address")
        # data_mem_table.column("#0", width=250)
        # data_mem_table.heading("#1", text="Value +0")
        # data_mem_table.column("#1", width=120)
        # data_mem_table.heading("#2", text="Value +4")
        # data_mem_table.column("#2", width=120)
        # data_mem_table.heading("#3", text="Value +8")
        # data_mem_table.column("#3", width=120)
        # data_mem_table.heading("#4", text="Value +C")
        # data_mem_table.column("#4", width=120)
        # data_mem_table.heading("#5", text="Value +10")
        # data_mem_table.column("#5", width=120)
        # data_mem_table.heading("#6", text="Value +14")
        # data_mem_table.column("#6", width=120)
        # data_mem_table.heading("#7", text="Value +18")
        # data_mem_table.column("#7", width=120)
        # data_mem_table.heading("#8", text="Value +1C")
        # data_mem_table.column("#8", width=120)
   

        # data_address = 0x10010000  # Başlangıç adresi
        # for i in range(1024):
        #     formatted_address = format(data_address, '08X')
        #     values = tuple([f"0x00000000"] * 8)  # Value sütunları için varsayılan değerler
        #     data_mem_table.insert("", "end", text=f"0x{formatted_address}", values=values + ("",))
        #     data_address += 0x20

        # data_mem_table.pack(fill="both", expand=True)

        


        self.register_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.register_tab, text="Registers")
        register_frame = ttk.Frame(self.register_tab)
        register_frame.pack(padx=5, pady=5)
        register_label = ttk.Label(register_frame, text="Registers")

        self.register_names = {
    '$zero': 0, '$at': 1, '$v0': 2, '$v1': 3, '$a0': 4, '$a1': 5, '$a2': 6, '$a3': 7,
    '$t0': 8, '$t1': 9, '$t2': 10, '$t3': 11, '$t4': 12, '$t5': 13, '$t6': 14, '$t7': 15,
    '$s0': 16, '$s1': 17, '$s2': 18, '$s3': 19, '$s4': 20, '$s5': 21, '$s6': 22, '$s7': 23,
    '$t8': 24, '$t9': 25, '$k0': 26, '$k1': 27, '$gp': 28, '$sp': 29, '$fp': 30, '$ra': 31,
    '$pc': "PC", '$hi': "HI", '$lo': "LO"
}

        register_label.pack()

        self.register_table = ttk.Treeview(register_frame, columns=("Register Name", "Number", "Value"), height=32)
        self.register_table.heading("Register Name", text="Register Name")
        self.register_table.heading("Number", text="Number")
        self.register_table.heading("Value", text="Value")
        self.register_table.column("#0", width=0, stretch="no")

        for reg_name, reg_num in self.register_names.items():
            if reg_name == "$sp":
                value = "0x7fffeffc"
            elif reg_name == "$gp":
                value = "0x10008000"
            elif reg_name == "$pc":
                value = "0x00400000"
            else:
                value = "0x00000000"
            self.register_table.insert("", "end", text=f"${reg_num}", values=(reg_name, reg_num, value))



        style = ttk.Style()
        style.configure("Treeview", font=("TkDefaultFont", 12))

        self.register_table.pack(side="right")

        self.window.mainloop()


if __name__ == "__main__":
    app = App()


