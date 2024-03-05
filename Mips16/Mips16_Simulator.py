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
        messagebox.showinfo("About", "This is a KGTU Mips simulator. This program was made by FURKAN ALİ TUNÇ, İLKAY TÜRE and HATİCE BETÜL ESEROĞLU. ")
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

    def result_code(self):

        self.run_code()

        self.message_text.delete("1.0", "end")
        self.message_text.insert("end", f"Operation completed successfully!\n")

        reg_values_sonadim = self.reg_text.get("1.0", "end-1c")
        reg_value_sonadim = reg_values_sonadim.split('\n')
        self.reg_text.delete("1.0", "end")

        for i in range(len(reg_value_sonadim)-10, len(reg_value_sonadim)):
            self.reg_text.insert("end", f"{reg_value_sonadim[i]}\n")

        memory_values_sonadim = self.memory_text.get("1.0", "end-1c")
        memory_value_sonadim = memory_values_sonadim.split('\n')
        self.memory_text.delete("1.0", "end")

        for i in range(len(memory_value_sonadim)-10, len(memory_value_sonadim)):
            self.memory_text.insert("end", f"{memory_value_sonadim[i]}\n")

        
        



    def reset_code(self):

        self.code_text.delete("1.0", "end")
        self.output_text.delete("1.0", "end")
        self.reg_text.delete("1.0", "end")
        self.memory_text.delete("1.0", "end")
        self.message_text.delete("1.0", "end")

        self.line_adim_index=0
        self.reg_adim_index=0
        self.pointer_adim_index=0

        self.reg_text.insert("end", f"$zero            0             0x000000 \n")
        self.reg_text.insert("end", f"$t0              1             0x000000 \n")
        self.reg_text.insert("end", f"$t1              2             0x000000 \n")
        self.reg_text.insert("end", f"$t2              3             0x000000 \n")
        self.reg_text.insert("end", f"$s0              4             0x000000 \n")
        self.reg_text.insert("end", f"$s1              5             0x000000 \n")
        self.reg_text.insert("end", f"$sp              6             0x000000 \n")
        self.reg_text.insert("end", f"$ra              7             0x000000 \n")
        self.reg_text.insert("end", f"————————————————————————————————————————\n")    


    def adim_code(self):
        self.run_code()

        #lines_adimadim = self.output_text.get("1.0", "end-1c")
        #line_adim = lines_adimadim.split('\n')

        reg_values_adimadim = self.reg_text.get("1.0", "end-1c")
        reg_value_adim = reg_values_adimadim.split('\n')

        # pointer_adimadim = self.pointer2_text.get("1.0", "end-1c")
        # pointer_adim = pointer_adimadim.split('\n')

        #print("pointer")
        #print(pointer_adim)

        #print(pointer_adim[self.pointer_adim_index])

        # self.pointer2_text.delete("1.0", "end")

        #print("*******")
        #print(lines_two[self.adim_index])

        #self.output_text.delete("1.0", "end")
        #self.output_text.insert("end", f"{line_adim[self.line_adim_index]}\n")

        self.reg_text.delete("1.0", "end")

        for i in range(self.reg_adim_index, self.reg_adim_index + 9):
            if i >= len(reg_value_adim):
                #self.reg_adim_index-=9
                i = i-10
                self.reg_adim_index-=1
                self.message_text.delete("1.0", "end")
                self.message_text.insert("end", f"Operation completed successfully!\n")
            self.reg_text.insert("end", f"{reg_value_adim[i]}\n")
            #print(reg_value_adim[i])

        # self.pointer_text.delete("1.0", "end")

        # line_counts = {
        #     '0': 0,
        #     '1': 1,
        #     '2': 2,
        # }

        # line_counts = {str(i): i for i in range(65)}

        # for _ in range(line_counts.get(pointer_adim[self.pointer_adim_index], 0)):
        #     self.pointer_text.insert("end", f"\n")

        # self.pointer_text.insert("end", f"****\n")

        # if pointer_adim[self.pointer_adim_index]=='0':
        #     self.pointer_text.delete("1.0", "end")
        #     self.pointer_text.insert("end", f"****\n")
        # elif pointer_adim[self.pointer_adim_index]=='1':
        #     self.pointer_text.delete("1.0", "end")
        #     self.pointer_text.insert("end", f"\n")
        #     self.pointer_text.insert("end", f"****\n")
        # elif pointer_adim[self.pointer_adim_index]=='2':
        #     self.pointer_text.delete("1.0", "end")
        #     self.pointer_text.insert("end", f"\n")
        #     self.pointer_text.insert("end", f"\n")
        #     self.pointer_text.insert("end", f"****\n")
        # else:
        #     prev_space = pointer_adim[self.pointer_adim_index]
        #     for _ in range(prev_space):
        #         self.pointer_text.delete("1.0", "end")
        #         self.pointer_text.insert("end", f"\n")
        #     self.pointer_text.insert("end", f"****\n")

        # self.pointer_adim_index+=1
        #self.line_adim_index+=1
        self.reg_adim_index+=9
    

    def run_code(self):

        self.output_text.delete("1.0", "end")
        self.reg_text.delete("1.0", "end")
        self.memory_text.delete("1.0", "end")

        # self.memory = [0] * 1024
        base_address = 0x0000

        numberLine = 0
        code = self.code_text.get("1.0", "end-1c")

        lines = code.split('\n')

        direction = {}
        for i in range(0,50):
            direction[i] = -1

        register_names = {
            '$zero': 0, '$t0': 1, '$t1': 2, '$t2': 3, '$s0': 4, '$s1': 5, '$sp': 6, '$ra': 7,
        }

        register_values = {'$zero': 0, '$t0': 0, '$t1': 0, '$t2': 0, '$s0': 0, '$s1': 0, '$sp': 0, '$ra': 0, }

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

        def get_hex_number(registers):
            return 0x0000

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

            hex_str = hex_str.rjust(6, '0')

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

        # MEMORY_SIZE = 1024
        # memory = [0] * MEMORY_SIZE

        memory_values= {'0x100100': 0, '0x100102': 0, '0x100104': 0, '0x100106': 0, '0x100108': 0, '0x10010a': 0,}
        memory_byte_values={}

        memory_values_updated= {'0x000010': format_hex(0), '0x000012': format_hex(0), '0x000014': format_hex(0), '0x000016': format_hex(0), '0x000018': format_hex(0), 
                                '0x00001a': format_hex(0), '0x00001c': format_hex(0), '0x00001e': format_hex(0),}

        def write_memory(address, data):
            # if address < 0 or address >= MEMORY_SIZE:
            #     raise ValueError(f"Memory access error: address out of bounds ({address})")
            #memory_values[hex(address)] = format_hex(data)
            memory_values_updated[format_hex(address)] = format_hex(data)
            #memory[address] = data & 0xFF

        def read_memory(address):
            # if address < 0 or address >= MEMORY_SIZE:
            #     raise ValueError(f"Memory access error: address out of bounds ({address})")
            #valueee = memory_values[hex(address)]
            valueee = memory_values_updated[format_hex(address)]
            return valueee
        
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

                    binary = f'{opcode}{rs:03b}{rt:03b}{rd:03b}00'

                    hexcode = binary_to_hex(binary)

                    self.output_text.insert("end", f"   {format_hex(base_address)}                           {hexcode}                 {binary}      {line}\n")
                    register_values[args[0]] = register_values[args[1]] + register_values[args[2]]
                    #self.reg_text.insert("end", f"Name:{args[0]}---Number:{rd}----Value:{format_hex(register_values[args[0]])} \n") # = /**Eklenenİlk: {register_values[args[1]]}  + Eklenen2:  {imm}*//

                    numberLine += 1
                    base_address += 2

                    # del words[:4]
                    words = words[4:]
                    #print(words)

                elif instruction == 'sub':
                    rd = register_names[args[0]]
                    rs = register_names[args[1]]
                    rt = register_names[args[2]]

                    opcode = opcode_to_binary[instruction]

                    binary = f'{opcode}{rs:03b}{rt:03b}{rd:03b}00'

                    hexcode = binary_to_hex(binary)

                    self.output_text.insert("end", f"   {format_hex(base_address)}                           {hexcode}                 {binary}      {line}\n")
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
                    base_address += 2

                    # del words[:4]
                    words = words[4:]
                    #print(words)

                elif instruction == 'and':
                    rd = register_names[args[0]]
                    rs = register_names[args[1]]
                    rt = register_names[args[2]]

                    opcode = opcode_to_binary[instruction]

                    binary = f'{opcode}{rs:03b}{rt:03b}{rd:03b}00'

                    hexcode = binary_to_hex(binary)

                    # direction[numberLine] = None
                    # print("and none")

                    self.output_text.insert("end", f"   {format_hex(base_address)}                           {hexcode}                 {binary}      {line}\n")
                    register_values[args[0]] = register_values[args[1]] & register_values[args[2]]
                    #self.reg_text.insert("end", f"Name:{args[0]}---Number:{rd}----Value:{format_hex(register_values[args[0]])} \n")

                    base_address += 2
                    numberLine += 1

                    # del words[:4]
                    words = words[4:]
                    #print(words)

                elif instruction == 'or':
                    rd = register_names[args[0]]
                    rs = register_names[args[1]]
                    rt = register_names[args[2]]

                    opcode = opcode_to_binary[instruction]

                    binary = f'{opcode}{rs:03b}{rt:03b}{rd:03b}00'

                    hexcode = binary_to_hex(binary)

                    self.output_text.insert("end", f"   {format_hex(base_address)}                           {hexcode}                 {binary}      {line}\n")
                    register_values[args[0]] = register_values[args[1]] | register_values[args[2]]
                    # self.reg_text.insert("end", f"Name:{args[0]}---Number:{rd}----Value:{format_hex(register_values[args[0]])} \n")

                    base_address += 2
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

                    self.output_text.insert("end", f"   {format_hex(base_address)}                           {hexcode}                 {binary}      {line}\n")
                    register_values[args[0]] = register_values[args[1]] + imm
                    # self.reg_text.insert("end", f"Name:{args[0]}---Number:{rt}----Value:{format_hex(register_values[args[0]])} \n") # = /**Eklenenİlk: {register_values[args[1]]}  + Eklenen2:  {imm}*//

                    base_address += 2
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

                    self.output_text.insert("end", f"   {format_hex(base_address)}                           {hexcode}                 {binary}      {line}\n")
                    register_values[args[0]] = register_values[args[1]] & imm
                    # self.reg_text.insert("end", f"Name:{args[0]}---Number:{rt}----Value:{format_hex(register_values[args[0]])} \n")

                    base_address += 2
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

                    self.output_text.insert("end", f"   {format_hex(base_address)}                           {hexcode}                 {binary}      {line}\n")
                    register_values[args[0]] = register_values[args[1]] | imm
                    # self.reg_text.insert("end", f"Name:{args[0]}---Number:{rt}----Value:{format_hex(register_values[args[0]])} \n")

                    base_address += 2
                    numberLine += 1

                    # del words[:4]
                    words = words[4:]
                    #print(words)

                elif instruction == 'xor':
                    rd = register_names[args[0]]
                    rs = register_names[args[1]]
                    rt = register_names[args[2]]

                    opcode = opcode_to_binary[instruction]

                    binary = f'{opcode}{rs:03b}{rt:03b}{rd:03b}00'

                    hexcode = binary_to_hex(binary)

                    self.output_text.insert("end", f"   {format_hex(base_address)}                           {hexcode}                 {binary}      {line}\n")
                    register_values[args[0]] = register_values[args[1]] ^ register_values[args[2]]
                    # self.reg_text.insert("end", f"Name:{args[0]}---Number:{rd}----Value:{format_hex(register_values[args[0]])} \n")

                    base_address += 2
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

                    binary = f'{opcode}000{rt:03b}{rd:03b}{shamt:02b}'

                    hexcode = binary_to_hex(binary)

                    self.output_text.insert("end", f"   {format_hex(base_address)}                           {hexcode}                 {binary}      {line}\n")

                    register_values[args[0]] = register_values[args[1]] << shamt

                    # self.reg_text.insert("end", f"Name:{args[0]}---Number:{rd}----Value:{format_hex(register_values[args[0]])} \n")

                    base_address += 2
                    numberLine += 1

                    # del words[:4]
                    words = words[4:]

                elif instruction == 'srl':
                    rd = register_names[args[0]]
                    rt = register_names[args[1]]
                    shamt = int(args[2])

                    opcode = opcode_to_binary[instruction]

                    binary = f'{opcode}000{rt:03b}{rd:03b}{shamt:02b}'

                    hexcode = binary_to_hex(binary)

                    self.output_text.insert("end", f"   {format_hex(base_address)}                           {hexcode}                 {binary}      {line}\n")

                    register_values[args[0]] = register_values[args[1]] >> shamt

                    # self.reg_text.insert("end", f"Name:{args[0]}---Number:{rd}----Value:{format_hex(register_values[args[0]])} \n")

                    base_address += 2
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

                    pc = target_line_number * 2
                    target_address = 0x0000 + pc
                    numberLine-=2

                    direction[numberLine] = target_line_number

                    opcode = opcode_to_binary[instruction]
                    binary = f'{opcode}{rs:03b}00000000'
                    hexcode = binary_to_hex(binary)
                    self.output_text.insert("end", f"   {format_hex(base_address)}                           {hexcode}                 {binary}      jr $ra\n")
                    #pc = register_values[args[0]]

                    #base_address = pc
                    #self.reg_text.insert("end", f"JR--UPDATE Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")

                    # del words[:4]
                    base_address += 2
                    numberLine += 1
                    words = words[4:]
                    #print(direction)

                elif instruction == 'lw':
                    rt = register_names[args[0]]
                    offset = get_imm_value_lw(args[1])

                    opcode = opcode_to_binary[instruction]

                    binary = f'{opcode}{register_names[args[2]]:03b}{rt:03b}{offset:05b}'

                    hexcode = binary_to_hex(binary)

                    self.output_text.insert("end", f"   {format_hex(base_address)}                           {hexcode}                 {binary}      {line}\n")

                    # address = register_values[args[2]] + offset
                    # data = read_memory(address)
                    # register_values[args[0]] = data
                    # self.reg_text.insert("end", f"Name:{args[0]}---Number:{rt}----Value:{format_hex(register_values[args[0]])} \n")

                    # formatted_address = format(address, '08x')
                    # formatted_data = format(data, '08x')
                    # self.output_text.insert("end", f"Accessed Memory: Address: 0x{formatted_address}        Data: 0x{formatted_data}\n")
                    
                    base_address += 2
                    numberLine += 1

                    # del words[:4]
                    words = words[4:]
                    #print(words)

                elif instruction == 'sw':
                    rt = register_names[args[0]]
                    offset = get_imm_value(args[1])

                    opcode = opcode_to_binary[instruction]
                    binary = f'{opcode}{register_names[args[2]]:03b}{rt:03b}{offset:05b}'

                    hexcode = binary_to_hex(binary)

                    self.output_text.insert("end", f"   {format_hex(base_address)}                           {hexcode}                 {binary}      {line}\n")

                    # address = register_values[args[2]] + offset
                    # data = register_values[args[0]]
                    # write_memory(address, data)
                    #self.memory_text.insert("end", f"Accessed Memory: Address: {format_hex(address)}        Data: {format_hex(data)}\n")
                    # self.output_text.insert("end", f"Accessed Memory: Address: 0x{formatted_address}        Data: 0x{formatted_data}\n")

                    base_address += 2
                    numberLine += 1
                    words = words[4:]

                elif instruction == 'beq':
                    rs = args[0]
                    rt = args[1]
                    label = args[2]

                    beq_output_text_line = line


                    target_line_number = -1
                    for i, line in enumerate(lines):
                        if line.startswith(label + ':'):
                            target_line_number = i
                            break

                    if target_line_number == -1:
                        raise ValueError(f"Label '{label}' not found")

                    pc = target_line_number * 2
                    if(target_line_number>numberLine):
                        pc_beq= (target_line_number-numberLine)-1
                    else:
                        pc_beq= (numberLine-target_line_number)-1
                    target_address = 0x0000 + pc

                    if(register_values[rs]==register_values[rt]):
                        direction[numberLine] = target_line_number

                    rs = register_names[args[0]]
                    rt = register_names[args[1]]
                    opcode = opcode_to_binary[instruction]
                    binary = f'{opcode}{rs:03b}{rt:03b}{pc_beq:05b}'
                    hexcode = binary_to_hex(binary)
                    self.output_text.insert("end", f"   {format_hex(base_address)}                           {hexcode}                 {binary}      {beq_output_text_line}\n")
                    base_address += 2
                    numberLine += 1
                    words = []
                    continue

                elif instruction == 'bne':
                    rs = args[0]
                    rt = args[1]
                    label = args[2]

                    bne_output_text_line = line

                    #print(register_values[rs])
                    #print(register_values[rt])

                    target_line_number = -1
                    for i, line in enumerate(lines):
                        if line.startswith(label + ':'):
                            target_line_number = i
                            break

                    if target_line_number == -1:
                        raise ValueError(f"Label '{label}' not found")

                    pc = target_line_number * 2
                    if(target_line_number>numberLine):
                        pc_bne= (target_line_number-numberLine)-1
                    else:
                        pc_bne= (numberLine-target_line_number)-1
                    target_address = 0x0000 + pc

                    if(register_values[rs]!=register_values[rt]):
                        direction[numberLine] = target_line_number

                    rs = register_names[args[0]]
                    rt = register_names[args[1]]
                    opcode = opcode_to_binary[instruction]
                    binary = f'{opcode}{rs:03b}{rt:03b}{pc_bne:05b}'    ## PC BEQ YERINE BNE
                    hexcode = binary_to_hex(binary)

                    self.output_text.insert("end", f"   {format_hex(base_address)}                           {hexcode}                 {binary}      {bne_output_text_line}\n")
                    base_address += 2
                    numberLine += 1
                    words = []
                    continue

                elif instruction == 'jal':
                    label = args[0]

                    j_output_text_line = line

                    target_line_number = -1
                    for i, line in enumerate(lines):
                        if line.startswith(label + ':'):
                            target_line_number = i
                            break

                    if target_line_number == -1:
                        raise ValueError(f"Label '{label}' not found")

                    pc = target_line_number * 2
                    pc_jal = target_line_number * 1
                    target_address = 0x0000 + pc

                    direction[numberLine] = target_line_number

                    #print(direction)
                    opcode = opcode_to_binary[instruction]
                    binary = f'{opcode}{pc_jal:011b}'
                    hexcode = binary_to_hex(binary)
                    self.output_text.insert("end", f"   {format_hex(base_address)}                           {hexcode}                 {binary}      {j_output_text_line}\n")
                    base_address += 2
                    numberLine += 1
                    words = []
                    continue

                elif instruction == 'j':

                    label = args[0]

                    j_output_text_line = line

                    target_line_number = -1
                    for i, line in enumerate(lines):
                        if line.startswith(label + ':'):
                            target_line_number = i
                            break

                    if target_line_number == -1:
                        raise ValueError(f"Label '{label}' not found")

                    pc = target_line_number * 2
                    pc_j = target_line_number * 1
                    target_address = 0x0000 + pc

                    direction[numberLine] = target_line_number
                    #print(f"Target Line Number: {target_line_number}")
                    #print(direction)

                    #print(direction)
                    opcode = opcode_to_binary[instruction]
                    binary = f'{opcode}{pc_j:011b}'
                    hexcode = binary_to_hex(binary)
                    self.output_text.insert("end", f"   {format_hex(base_address)}                           {hexcode}                 {binary}      {j_output_text_line}\n")
                    base_address += 2 
                    numberLine += 1
                    words = []
                    continue
        
        #print("Part2")
        #print(f"Direction:  {direction}")
        #self.output_text.insert("end",f"******************************************** \n")
        #self.reg_text.insert("end",f"******************************************** \n")
        #self.memory_text.insert("end",f"******************************************** \n")
        base_address = 0x0000
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

        register_values = {'$zero': 0, '$t0': 0, '$t1': 0, '$t2': 0, '$s0': 0, '$s1': 0, '$sp': 0, '$ra': 0, }

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
        base_address-=2

        while current_line < (len(lines)-1):

            base_address+=2
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

            # self.pointer2_text.insert("end", f"{current_line}\n")
            #print(f"{lines[current_line]}-----Base Add{base_address}") #burdan takip

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
                # self.reg_text.insert("end", f"Name:$zero---Number:{register_names['$zero']}----Value:{format_hex(register_values['$zero'])} \n")
                # self.reg_text.insert("end", f"Name:$t0-----Number:{register_names['$t0']}----Value:{format_hex(register_values['$t0'])} \n")
                # self.reg_text.insert("end", f"Name:$t1-----Number:{register_names['$t1']}----Value:{format_hex(register_values['$t1'])} \n")
                # self.reg_text.insert("end", f"Name:$t2-----Number:{register_names['$t2']}----Value:{format_hex(register_values['$t2'])} \n")
                # self.reg_text.insert("end", f"Name:$s0-----Number:{register_names['$s0']}----Value:{format_hex(register_values['$s0'])} \n")
                # self.reg_text.insert("end", f"Name:$s1-----Number:{register_names['$s1']}----Value:{format_hex(register_values['$s1'])} \n")
                # self.reg_text.insert("end", f"Name:$sp-----Number:{register_names['$sp']}----Value:{format_hex(register_values['$sp'])} \n")
                # self.reg_text.insert("end", f"Name:$ra-----Number:{register_names['$ra']}----Value:{format_hex(register_values['$ra'])} \n")
                # self.reg_text.insert("end", f"***************************************\n")
                pc_line-=2
                continue

            # print(line)
            # print(current_line)
            pc_line = current_line*2
            # self.memory_text.insert("end", f"{format_hex(pc_line)}\n")

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

                            pc = target_line_number * 2
                            target_address = 0x0000 + pc

                            direction[numberLine] = target_line_number

                            opcode = opcode_to_binary[instruction]
                            binary = f'{opcode}{rs:03b}{rt:03b}{pc_beq:05b}'
                            hexcode = binary_to_hex(binary)
                            #self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}      Jump: {hex(target_address)}\n")
                        
                        # self.reg_text.insert("end", f"Name:$zero---Number:{register_names['$zero']}----Value:{format_hex(register_values['$zero'])} \n")
                        # self.reg_text.insert("end", f"Name:$t0-----Number:{register_names['$t0']}----Value:{format_hex(register_values['$t0'])} \n")
                        # self.reg_text.insert("end", f"Name:$t1-----Number:{register_names['$t1']}----Value:{format_hex(register_values['$t1'])} \n")
                        # self.reg_text.insert("end", f"Name:$t2-----Number:{register_names['$t2']}----Value:{format_hex(register_values['$t2'])} \n")
                        # self.reg_text.insert("end", f"Name:$s0-----Number:{register_names['$s0']}----Value:{format_hex(register_values['$s0'])} \n")
                        # self.reg_text.insert("end", f"Name:$s1-----Number:{register_names['$s1']}----Value:{format_hex(register_values['$s1'])} \n")
                        # self.reg_text.insert("end", f"Name:$sp-----Number:{register_names['$sp']}----Value:{format_hex(register_values['$sp'])} \n")
                        # self.reg_text.insert("end", f"Name:$ra-----Number:{register_names['$ra']}----Value:{format_hex(register_values['$ra'])} \n")
                        # self.reg_text.insert("end", f"***************************************\n")
                        
                        # base_address += 2
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

                            pc = target_line_number * 2
                            target_address = 0x0000 + pc

                            direction[numberLine] = target_line_number

                            opcode = opcode_to_binary[instruction]
                            binary = f'{opcode}{rs:03b}{rt:03b}{pc:05b}'
                            hexcode = binary_to_hex(binary)
                            #self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}      Jump: {hex(target_address)}\n")
                        # base_address += 2
                        numberLine += 1
                        words = []
                        continue

                    elif instruction == 'add':
                        rd = register_names[args[0]]
                        rs = register_names[args[1]]
                        rt = register_names[args[2]]
                        opcode = opcode_to_binary[instruction]
                        binary = f'{opcode}{rs:03b}{rt:03b}{rd:03b}00'
                        hexcode = binary_to_hex(binary)
                        register_values[args[0]] = register_values[args[1]] + register_values[args[2]]

                        self.reg_text.insert("end", f"$zero            0             {format_hex(register_values['$zero'])} \n")
                        self.reg_text.insert("end", f"$t0              1             {format_hex(register_values['$t0'])}\n")
                        self.reg_text.insert("end", f"$t1              2             {format_hex(register_values['$t1'])}\n")
                        self.reg_text.insert("end", f"$t2              3             {format_hex(register_values['$t2'])}\n")
                        self.reg_text.insert("end", f"$s0              4             {format_hex(register_values['$s0'])}\n")
                        self.reg_text.insert("end", f"$s1              5             {format_hex(register_values['$s1'])}\n")
                        self.reg_text.insert("end", f"$sp              6             {format_hex(register_values['$sp'])}\n")
                        self.reg_text.insert("end", f"$ra              7             {format_hex(register_values['$ra'])}\n")
                        self.reg_text.insert("end", f"————————————————————————————————————————\n") 

                        self.memory_text.insert("end", f"Memory Address: 0x000010   Data: {read_memory(0x000010)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000012   Data: {read_memory(0x000012)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000014   Data: {read_memory(0x000014)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000016   Data: {read_memory(0x000016)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000018   Data: {read_memory(0x000018)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x00001a   Data: {read_memory(0x00001a)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x00001c   Data: {read_memory(0x00001c)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x00001e   Data: {read_memory(0x00001e)}\n")
                        self.memory_text.insert("end", f"————————————————————————————————————————\n") 

                        #self.reg_text.insert("end", f"Name:{args[0]}---Number:{rd}----Value:{format_hex(register_values[args[0]])} \n") # = /**Eklenenİlk: {register_values[args[1]]}  + Eklenen2:  {imm}*//


                        # base_address += 2
                        words = words[4:]
                            #print(words)

                    elif instruction == 'sub':
                        rd = register_names[args[0]]
                        rs = register_names[args[1]]
                        rt = register_names[args[2]]

                        opcode = opcode_to_binary[instruction]

                        binary = f'{opcode}{rs:03b}{rt:03b}{rd:03b}00'

                        hexcode = binary_to_hex(binary)

                        #self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")

                        if(register_values[args[2]] > register_values[args[1]]):

                            register_values[args[0]] = register_values[args[1]] - register_values[args[2]]  #-4

                            #register_values[args[0]] = twos_complement(register_values[args[0]])
                            #print(register_values[args[0]])
                            #print(hex(twos_complement(register_values[args[0]])))
                            self.reg_text.insert("end", f"$zero            0             {format_hex(register_values['$zero'])} \n")
                            self.reg_text.insert("end", f"$t0              1             {format_hex(register_values['$t0'])}\n")
                            self.reg_text.insert("end", f"$t1              2             {format_hex(register_values['$t1'])}\n")
                            self.reg_text.insert("end", f"$t2              3             {format_hex(register_values['$t2'])}\n")
                            self.reg_text.insert("end", f"$s0              4             {format_hex(register_values['$s0'])}\n")
                            self.reg_text.insert("end", f"$s1              5             {format_hex(register_values['$s1'])}\n")
                            self.reg_text.insert("end", f"$sp              6             {format_hex(register_values['$sp'])}\n")
                            self.reg_text.insert("end", f"$ra              7             {format_hex(register_values['$ra'])}\n")
                            self.reg_text.insert("end", f"————————————————————————————————————————\n")      

                            self.memory_text.insert("end", f"Memory Address: 0x000010   Data: {read_memory(0x000010)}\n")
                            self.memory_text.insert("end", f"Memory Address: 0x000012   Data: {read_memory(0x000012)}\n")
                            self.memory_text.insert("end", f"Memory Address: 0x000014   Data: {read_memory(0x000014)}\n")
                            self.memory_text.insert("end", f"Memory Address: 0x000016   Data: {read_memory(0x000016)}\n")
                            self.memory_text.insert("end", f"Memory Address: 0x000018   Data: {read_memory(0x000018)}\n")
                            self.memory_text.insert("end", f"Memory Address: 0x00001a   Data: {read_memory(0x00001a)}\n")
                            self.memory_text.insert("end", f"Memory Address: 0x00001c   Data: {read_memory(0x00001c)}\n")
                            self.memory_text.insert("end", f"Memory Address: 0x00001e   Data: {read_memory(0x00001e)}\n")
                            self.memory_text.insert("end", f"————————————————————————————————————————\n") 

                            #self.reg_text.insert("end", f"Name:{args[0]}---Number:{rd}----Value:{twos_complement(register_values[args[0]])} \n") # = /**Eklenenİlk: {register_values[args[1]]}  + Eklenen2:  {imm}*//

                        else:
                            register_values[args[0]] = register_values[args[1]] - register_values[args[2]]

                            self.reg_text.insert("end", f"$zero            0             {format_hex(register_values['$zero'])} \n")
                            self.reg_text.insert("end", f"$t0              1             {format_hex(register_values['$t0'])}\n")
                            self.reg_text.insert("end", f"$t1              2             {format_hex(register_values['$t1'])}\n")
                            self.reg_text.insert("end", f"$t2              3             {format_hex(register_values['$t2'])}\n")
                            self.reg_text.insert("end", f"$s0              4             {format_hex(register_values['$s0'])}\n")
                            self.reg_text.insert("end", f"$s1              5             {format_hex(register_values['$s1'])}\n")
                            self.reg_text.insert("end", f"$sp              6             {format_hex(register_values['$sp'])}\n")
                            self.reg_text.insert("end", f"$ra              7             {format_hex(register_values['$ra'])}\n")
                            self.reg_text.insert("end", f"————————————————————————————————————————\n") 

                            self.memory_text.insert("end", f"Memory Address: 0x000010   Data: {read_memory(0x000010)}\n")
                            self.memory_text.insert("end", f"Memory Address: 0x000012   Data: {read_memory(0x000012)}\n")
                            self.memory_text.insert("end", f"Memory Address: 0x000014   Data: {read_memory(0x000014)}\n")
                            self.memory_text.insert("end", f"Memory Address: 0x000016   Data: {read_memory(0x000016)}\n")
                            self.memory_text.insert("end", f"Memory Address: 0x000018   Data: {read_memory(0x000018)}\n")
                            self.memory_text.insert("end", f"Memory Address: 0x00001a   Data: {read_memory(0x00001a)}\n")
                            self.memory_text.insert("end", f"Memory Address: 0x00001c   Data: {read_memory(0x00001c)}\n")
                            self.memory_text.insert("end", f"Memory Address: 0x00001e   Data: {read_memory(0x00001e)}\n")
                            self.memory_text.insert("end", f"————————————————————————————————————————\n")    
                            
                            #self.reg_text.insert("end", f"Name:{args[0]}---Number:{rd}----Value:{format_hex(register_values[args[0]])} \n") # = /**Eklenenİlk: {register_values[args[1]]}  + Eklenen2:  {imm}*//

                        # base_address += 2

                        # del words[:4]
                        words = words[4:]
                        #print(words)

                    elif instruction == 'and':
                        rd = register_names[args[0]]
                        rs = register_names[args[1]]
                        rt = register_names[args[2]]

                        opcode = opcode_to_binary[instruction]

                        binary = f'{opcode}{rs:03b}{rt:03b}{rd:03b}00'

                        hexcode = binary_to_hex(binary)
                        #self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")
                        register_values[args[0]] = register_values[args[1]] & register_values[args[2]]

                        self.reg_text.insert("end", f"$zero            0             {format_hex(register_values['$zero'])} \n")
                        self.reg_text.insert("end", f"$t0              1             {format_hex(register_values['$t0'])}\n")
                        self.reg_text.insert("end", f"$t1              2             {format_hex(register_values['$t1'])}\n")
                        self.reg_text.insert("end", f"$t2              3             {format_hex(register_values['$t2'])}\n")
                        self.reg_text.insert("end", f"$s0              4             {format_hex(register_values['$s0'])}\n")
                        self.reg_text.insert("end", f"$s1              5             {format_hex(register_values['$s1'])}\n")
                        self.reg_text.insert("end", f"$sp              6             {format_hex(register_values['$sp'])}\n")
                        self.reg_text.insert("end", f"$ra              7             {format_hex(register_values['$ra'])}\n")
                        self.reg_text.insert("end", f"————————————————————————————————————————\n")

                        self.memory_text.insert("end", f"Memory Address: 0x000010   Data: {read_memory(0x000010)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000012   Data: {read_memory(0x000012)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000014   Data: {read_memory(0x000014)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000016   Data: {read_memory(0x000016)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000018   Data: {read_memory(0x000018)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x00001a   Data: {read_memory(0x00001a)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x00001c   Data: {read_memory(0x00001c)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x00001e   Data: {read_memory(0x00001e)}\n")
                        self.memory_text.insert("end", f"————————————————————————————————————————\n")    
                        #self.reg_text.insert("end", f"Name:{args[0]}---Number:{rd}----Value:{format_hex(register_values[args[0]])} \n")

                        # base_address += 2

                        # del words[:4]
                        words = words[4:]
                        #print(words)

                    elif instruction == 'or':
                        rd = register_names[args[0]]
                        rs = register_names[args[1]]
                        rt = register_names[args[2]]
                        opcode = opcode_to_binary[instruction]

                        binary = f'{opcode}{rs:03b}{rt:03b}{rd:03b}00'

                        hexcode = binary_to_hex(binary)

                        register_values[args[0]] = register_values[args[1]] | register_values[args[2]]

                        self.reg_text.insert("end", f"$zero            0             {format_hex(register_values['$zero'])} \n")
                        self.reg_text.insert("end", f"$t0              1             {format_hex(register_values['$t0'])}\n")
                        self.reg_text.insert("end", f"$t1              2             {format_hex(register_values['$t1'])}\n")
                        self.reg_text.insert("end", f"$t2              3             {format_hex(register_values['$t2'])}\n")
                        self.reg_text.insert("end", f"$s0              4             {format_hex(register_values['$s0'])}\n")
                        self.reg_text.insert("end", f"$s1              5             {format_hex(register_values['$s1'])}\n")
                        self.reg_text.insert("end", f"$sp              6             {format_hex(register_values['$sp'])}\n")
                        self.reg_text.insert("end", f"$ra              7             {format_hex(register_values['$ra'])}\n")
                        self.reg_text.insert("end", f"————————————————————————————————————————\n")

                        self.memory_text.insert("end", f"Memory Address: 0x000010   Data: {read_memory(0x000010)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000012   Data: {read_memory(0x000012)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000014   Data: {read_memory(0x000014)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000016   Data: {read_memory(0x000016)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000018   Data: {read_memory(0x000018)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x00001a   Data: {read_memory(0x00001a)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x00001c   Data: {read_memory(0x00001c)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x00001e   Data: {read_memory(0x00001e)}\n")
                        self.memory_text.insert("end", f"————————————————————————————————————————\n")       
                        #self.reg_text.insert("end", f"Name:{args[0]}---Number:{rd}----Value:{format_hex(register_values[args[0]])} \n")

                        # base_address += 2

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

                        #self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")
                        register_values[args[0]] = register_values[args[1]] + imm

                        #self.reg_text.delete("1.0", "end")

                        self.reg_text.insert("end", f"$zero            0             {format_hex(register_values['$zero'])} \n")
                        self.reg_text.insert("end", f"$t0              1             {format_hex(register_values['$t0'])}\n")
                        self.reg_text.insert("end", f"$t1              2             {format_hex(register_values['$t1'])}\n")
                        self.reg_text.insert("end", f"$t2              3             {format_hex(register_values['$t2'])}\n")
                        self.reg_text.insert("end", f"$s0              4             {format_hex(register_values['$s0'])}\n")
                        self.reg_text.insert("end", f"$s1              5             {format_hex(register_values['$s1'])}\n")
                        self.reg_text.insert("end", f"$sp              6             {format_hex(register_values['$sp'])}\n")
                        self.reg_text.insert("end", f"$ra              7             {format_hex(register_values['$ra'])}\n")
                        self.reg_text.insert("end", f"————————————————————————————————————————\n")

                        self.memory_text.insert("end", f"Memory Address: 0x000010   Data: {read_memory(0x000010)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000012   Data: {read_memory(0x000012)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000014   Data: {read_memory(0x000014)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000016   Data: {read_memory(0x000016)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000018   Data: {read_memory(0x000018)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x00001a   Data: {read_memory(0x00001a)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x00001c   Data: {read_memory(0x00001c)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x00001e   Data: {read_memory(0x00001e)}\n")
                        self.memory_text.insert("end", f"————————————————————————————————————————\n") 

                        # self.reg_text.insert("end", f"Nameee:{args[0]}---Number:{rt}----Value:{format_hex(register_values[args[0]])} \n") # = /**Eklenenİlk: {register_values[args[1]]}  + Eklenen2:  {imm}*//

                        # base_address += 2

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

                        #self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")
                        register_values[args[0]] = register_values[args[1]] & imm

                        self.reg_text.insert("end", f"$zero            0             {format_hex(register_values['$zero'])} \n")
                        self.reg_text.insert("end", f"$t0              1             {format_hex(register_values['$t0'])}\n")
                        self.reg_text.insert("end", f"$t1              2             {format_hex(register_values['$t1'])}\n")
                        self.reg_text.insert("end", f"$t2              3             {format_hex(register_values['$t2'])}\n")
                        self.reg_text.insert("end", f"$s0              4             {format_hex(register_values['$s0'])}\n")
                        self.reg_text.insert("end", f"$s1              5             {format_hex(register_values['$s1'])}\n")
                        self.reg_text.insert("end", f"$sp              6             {format_hex(register_values['$sp'])}\n")
                        self.reg_text.insert("end", f"$ra              7             {format_hex(register_values['$ra'])}\n")
                        self.reg_text.insert("end", f"————————————————————————————————————————\n")

                        self.memory_text.insert("end", f"Memory Address: 0x000010   Data: {read_memory(0x000010)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000012   Data: {read_memory(0x000012)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000014   Data: {read_memory(0x000014)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000016   Data: {read_memory(0x000016)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000018   Data: {read_memory(0x000018)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x00001a   Data: {read_memory(0x00001a)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x00001c   Data: {read_memory(0x00001c)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x00001e   Data: {read_memory(0x00001e)}\n")
                        self.memory_text.insert("end", f"————————————————————————————————————————\n")   
                        #self.reg_text.insert("end", f"Name:{args[0]}---Number:{rt}----Value:{format_hex(register_values[args[0]])} \n")

                        # base_address += 2

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

                        #self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")
                        register_values[args[0]] = register_values[args[1]] | imm

                        self.reg_text.insert("end", f"$zero            0             {format_hex(register_values['$zero'])} \n")
                        self.reg_text.insert("end", f"$t0              1             {format_hex(register_values['$t0'])}\n")
                        self.reg_text.insert("end", f"$t1              2             {format_hex(register_values['$t1'])}\n")
                        self.reg_text.insert("end", f"$t2              3             {format_hex(register_values['$t2'])}\n")
                        self.reg_text.insert("end", f"$s0              4             {format_hex(register_values['$s0'])}\n")
                        self.reg_text.insert("end", f"$s1              5             {format_hex(register_values['$s1'])}\n")
                        self.reg_text.insert("end", f"$sp              6             {format_hex(register_values['$sp'])}\n")
                        self.reg_text.insert("end", f"$ra              7             {format_hex(register_values['$ra'])}\n")
                        self.reg_text.insert("end", f"————————————————————————————————————————\n")

                        self.memory_text.insert("end", f"Memory Address: 0x000010   Data: {read_memory(0x000010)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000012   Data: {read_memory(0x000012)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000014   Data: {read_memory(0x000014)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000016   Data: {read_memory(0x000016)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000018   Data: {read_memory(0x000018)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x00001a   Data: {read_memory(0x00001a)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x00001c   Data: {read_memory(0x00001c)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x00001e   Data: {read_memory(0x00001e)}\n")
                        self.memory_text.insert("end", f"————————————————————————————————————————\n")    
                        #self.reg_text.insert("end", f"Name:{args[0]}---Number:{rt}----Value:{format_hex(register_values[args[0]])} \n")

                        # base_address += 2

                        # del words[:4]
                        words = words[4:]
                        #print(words)

                    elif instruction == 'xor':

                        rd = register_names[args[0]]
                        rs = register_names[args[1]]
                        rt = register_names[args[2]]

                        opcode = opcode_to_binary[instruction]

                        binary = f'{opcode}{rs:03b}{rt:03b}{rd:03b}00'

                        hexcode = binary_to_hex(binary)

                        #self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")
                        register_values[args[0]] = register_values[args[1]] ^ register_values[args[2]]

                        self.reg_text.insert("end", f"$zero            0             {format_hex(register_values['$zero'])} \n")
                        self.reg_text.insert("end", f"$t0              1             {format_hex(register_values['$t0'])}\n")
                        self.reg_text.insert("end", f"$t1              2             {format_hex(register_values['$t1'])}\n")
                        self.reg_text.insert("end", f"$t2              3             {format_hex(register_values['$t2'])}\n")
                        self.reg_text.insert("end", f"$s0              4             {format_hex(register_values['$s0'])}\n")
                        self.reg_text.insert("end", f"$s1              5             {format_hex(register_values['$s1'])}\n")
                        self.reg_text.insert("end", f"$sp              6             {format_hex(register_values['$sp'])}\n")
                        self.reg_text.insert("end", f"$ra              7             {format_hex(register_values['$ra'])}\n")
                        self.reg_text.insert("end", f"————————————————————————————————————————\n")

                        self.memory_text.insert("end", f"Memory Address: 0x000010   Data: {read_memory(0x000010)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000012   Data: {read_memory(0x000012)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000014   Data: {read_memory(0x000014)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000016   Data: {read_memory(0x000016)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000018   Data: {read_memory(0x000018)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x00001a   Data: {read_memory(0x00001a)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x00001c   Data: {read_memory(0x00001c)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x00001e   Data: {read_memory(0x00001e)}\n")
                        self.memory_text.insert("end", f"————————————————————————————————————————\n")    
                        #self.reg_text.insert("end", f"Name:{args[0]}---Number:{rd}----Value:{format_hex(register_values[args[0]])} \n")

                        # base_address += 2

                        # del words[:4]
                        words = words[4:]
                        #print(words)

                    elif instruction == 'sll':
                        rd = register_names[args[0]]
                        rt = register_names[args[1]]
                        shamt = int(args[2])

                        opcode = opcode_to_binary[instruction]

                        binary = f'{opcode}000{rt:03b}{rd:03b}{shamt:02b}'

                        hexcode = binary_to_hex(binary)

                        #self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")

                        register_values[args[0]] = register_values[args[1]] << shamt

                        self.reg_text.insert("end", f"$zero            0             {format_hex(register_values['$zero'])} \n")
                        self.reg_text.insert("end", f"$t0              1             {format_hex(register_values['$t0'])}\n")
                        self.reg_text.insert("end", f"$t1              2             {format_hex(register_values['$t1'])}\n")
                        self.reg_text.insert("end", f"$t2              3             {format_hex(register_values['$t2'])}\n")
                        self.reg_text.insert("end", f"$s0              4             {format_hex(register_values['$s0'])}\n")
                        self.reg_text.insert("end", f"$s1              5             {format_hex(register_values['$s1'])}\n")
                        self.reg_text.insert("end", f"$sp              6             {format_hex(register_values['$sp'])}\n")
                        self.reg_text.insert("end", f"$ra              7             {format_hex(register_values['$ra'])}\n")
                        self.reg_text.insert("end", f"————————————————————————————————————————\n")

                        self.memory_text.insert("end", f"Memory Address: 0x000010   Data: {read_memory(0x000010)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000012   Data: {read_memory(0x000012)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000014   Data: {read_memory(0x000014)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000016   Data: {read_memory(0x000016)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000018   Data: {read_memory(0x000018)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x00001a   Data: {read_memory(0x00001a)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x00001c   Data: {read_memory(0x00001c)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x00001e   Data: {read_memory(0x00001e)}\n")
                        self.memory_text.insert("end", f"————————————————————————————————————————\n")    
                        #self.reg_text.insert("end", f"Name:{args[0]}---Number:{rd}----Value:{format_hex(register_values[args[0]])} \n")

                        # base_address += 2

                        # del words[:4]
                        words = words[4:]

                    elif instruction == 'srl':
                        rd = register_names[args[0]]
                        rt = register_names[args[1]]
                        shamt = int(args[2])

                        opcode = opcode_to_binary[instruction]

                        binary = f'{opcode}000{rt:03b}{rd:03b}{shamt:02b}'

                        hexcode = binary_to_hex(binary)

                        #self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")

                        register_values[args[0]] = register_values[args[1]] >> shamt

                        self.reg_text.insert("end", f"$zero            0             {format_hex(register_values['$zero'])} \n")
                        self.reg_text.insert("end", f"$t0              1             {format_hex(register_values['$t0'])}\n")
                        self.reg_text.insert("end", f"$t1              2             {format_hex(register_values['$t1'])}\n")
                        self.reg_text.insert("end", f"$t2              3             {format_hex(register_values['$t2'])}\n")
                        self.reg_text.insert("end", f"$s0              4             {format_hex(register_values['$s0'])}\n")
                        self.reg_text.insert("end", f"$s1              5             {format_hex(register_values['$s1'])}\n")
                        self.reg_text.insert("end", f"$sp              6             {format_hex(register_values['$sp'])}\n")
                        self.reg_text.insert("end", f"$ra              7             {format_hex(register_values['$ra'])}\n")
                        self.reg_text.insert("end", f"————————————————————————————————————————\n")

                        self.memory_text.insert("end", f"Memory Address: 0x000010   Data: {read_memory(0x000010)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000012   Data: {read_memory(0x000012)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000014   Data: {read_memory(0x000014)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000016   Data: {read_memory(0x000016)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000018   Data: {read_memory(0x000018)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x00001a   Data: {read_memory(0x00001a)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x00001c   Data: {read_memory(0x00001c)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x00001e   Data: {read_memory(0x00001e)}\n")
                        self.memory_text.insert("end", f"————————————————————————————————————————\n")     
                        #self.reg_text.insert("end", f"Name:{args[0]}---Number:{rd}----Value:{format_hex(register_values[args[0]])} \n")

                        # base_address += 2

                        # del words[:4]
                        words = words[4:]

                    elif instruction == 'jr':
                        rs = register_names[args[0]]


                        opcode = opcode_to_binary[instruction]
                        binary = f'{opcode}{rs:03b}00000000'
                        hexcode = binary_to_hex(binary)
                        # self.output_text.insert("end", f"JR--Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")
                        #pc = register_values[args[0]]
                        #base_address = pc
                        #self.reg_text.insert("end", f"$8(vaddr): {format_hex(register_values[args[0]])}---$14(epc): {format_hex(register_values[args[0]])}  \n")

                        # self.reg_text.insert("end", f"Name:$zero---Number:{register_names['$zero']}----Value:{format_hex(register_values['$zero'])} \n")
                        # self.reg_text.insert("end", f"Name:$t0-----Number:{register_names['$t0']}----Value:{format_hex(register_values['$t0'])} \n")
                        # self.reg_text.insert("end", f"Name:$t1-----Number:{register_names['$t1']}----Value:{format_hex(register_values['$t1'])} \n")
                        # self.reg_text.insert("end", f"Name:$t2-----Number:{register_names['$t2']}----Value:{format_hex(register_values['$t2'])} \n")
                        # self.reg_text.insert("end", f"Name:$s0-----Number:{register_names['$s0']}----Value:{format_hex(register_values['$s0'])} \n")
                        # self.reg_text.insert("end", f"Name:$s1-----Number:{register_names['$s1']}----Value:{format_hex(register_values['$s1'])} \n")
                        # self.reg_text.insert("end", f"Name:$sp-----Number:{register_names['$sp']}----Value:{format_hex(register_values['$sp'])} \n")
                        # self.reg_text.insert("end", f"Name:$ra-----Number:{register_names['$ra']}----Value:{format_hex(register_values['$ra'])} \n")
                        # self.reg_text.insert("end", f"***************************************\n")   
                        # del words[:4]
                        # base_address += 2
                        words = words[4:]
                        #print(f"JRLine: {line}")
                        #print(f"Direction: {direction}")

                    elif instruction == 'lw':
                        rt = register_names[args[0]]
                        offset = get_imm_value_lw(args[1])

                        opcode = opcode_to_binary[instruction]

                        binary = f'{opcode}{register_names[args[2]]:03b}{rt:03b}{offset:05b}'

                        hexcode = binary_to_hex(binary)

                        # self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")

                        #print(memory_values)

                        address = register_values[args[2]] + offset

                        data = memory_values_updated[format_hex(address)]
                        #print(data)

                        decimal = int(data, 16) 
                        register_values[args[0]] = decimal

                        #print(register_values['$t0'])
                        #print(decimal)

                        #self.reg_text.insert("end", f"Accessed Memory: Address: {hex(address)}        Data: {data}\n")

                        self.reg_text.insert("end", f"$zero            0             {format_hex(register_values['$zero'])} \n")
                        self.reg_text.insert("end", f"$t0              1             {format_hex(register_values['$t0'])}\n")
                        self.reg_text.insert("end", f"$t1              2             {format_hex(register_values['$t1'])}\n")
                        self.reg_text.insert("end", f"$t2              3             {format_hex(register_values['$t2'])}\n")
                        self.reg_text.insert("end", f"$s0              4             {format_hex(register_values['$s0'])}\n")
                        self.reg_text.insert("end", f"$s1              5             {format_hex(register_values['$s1'])}\n")
                        self.reg_text.insert("end", f"$sp              6             {format_hex(register_values['$sp'])}\n")
                        self.reg_text.insert("end", f"$ra              7             {format_hex(register_values['$ra'])}\n")
                        self.reg_text.insert("end", f"————————————————————————————————————————\n")

                        self.memory_text.insert("end", f"Memory Address: 0x000010   Data: {read_memory(0x000010)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000012   Data: {read_memory(0x000012)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000014   Data: {read_memory(0x000014)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000016   Data: {read_memory(0x000016)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000018   Data: {read_memory(0x000018)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x00001a   Data: {read_memory(0x00001a)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x00001c   Data: {read_memory(0x00001c)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x00001e   Data: {read_memory(0x00001e)}\n")
                        self.memory_text.insert("end", f"————————————————————————————————————————\n")      
                        #self.reg_text.insert("end", f"Name:{args[0]}---Number:{rt}----Value:{data} \n")

                        # formatted_address = format(address, '08x')
                        # formatted_data = format(data, '08x')

                        #self.reg_text.insert("end", f"Name:{args[0]}---Number:{rt}----Value:{format_hex(register_values[args[0]])}----$8(vaddr):0x{formatted_address}----$14(epc):{hex(now_address_lw)}  \n")

                        # self.output_text.insert("end", f"Accessed Memory: Address: 0x{formatted_address}        Data: 0x{formatted_data}\n")

                        # base_address += 2
                        # del words[:4]
                        words = words[4:]
                        #print(words)
                    
                    elif instruction == 'sw':
                        rt = register_names[args[0]]
                        offset = get_imm_value(args[1])

                        opcode = opcode_to_binary[instruction]
                        binary = f'{opcode}{register_names[args[2]]:03b}{rt:03b}{offset:05b}'


                        hexcode = binary_to_hex(binary)

                        now_address_sw =base_address

                        # self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}\n")

                        address = register_values[args[2]] + offset
                        data = register_values[args[0]]

                        #print(address)
                        #print(data)

                        write_memory(address, data)

                        # print(memory_values_updated)

                        self.reg_text.insert("end", f"$zero            0             {format_hex(register_values['$zero'])} \n")
                        self.reg_text.insert("end", f"$t0              1             {format_hex(register_values['$t0'])}\n")
                        self.reg_text.insert("end", f"$t1              2             {format_hex(register_values['$t1'])}\n")
                        self.reg_text.insert("end", f"$t2              3             {format_hex(register_values['$t2'])}\n")
                        self.reg_text.insert("end", f"$s0              4             {format_hex(register_values['$s0'])}\n")
                        self.reg_text.insert("end", f"$s1              5             {format_hex(register_values['$s1'])}\n")
                        self.reg_text.insert("end", f"$sp              6             {format_hex(register_values['$sp'])}\n")
                        self.reg_text.insert("end", f"$ra              7             {format_hex(register_values['$ra'])}\n")
                        self.reg_text.insert("end", f"————————————————————————————————————————\n")    

                        #self.memory_text.delete("1.0", "end")
                        self.memory_text.insert("end", f"Memory Address: 0x000010   Data: {read_memory(0x000010)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000012   Data: {read_memory(0x000012)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000014   Data: {read_memory(0x000014)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000016   Data: {read_memory(0x000016)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000018   Data: {read_memory(0x000018)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x00001a   Data: {read_memory(0x00001a)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x00001c   Data: {read_memory(0x00001c)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x00001e   Data: {read_memory(0x00001e)}\n")
                        self.memory_text.insert("end", f"————————————————————————————————————————\n")    


                        #print(memory_values)

                        # formatted_address = format(address, '08x')
                        # formatted_data = format(data, '08x')

                        #self.reg_text.insert("end", f"Name:{args[0]}---Number:{rt}----Value:{format_hex(register_values[args[0]])}----$8(vaddr):0x{formatted_address}----$14(epc):{hex(now_address_sw)}  \n")

                        # self.output_text.insert("end", f"Accessed Memory: Address: 0x{formatted_address}        Data: 0x{formatted_data}\n")
                        # base_address += 2
                        words = words[4:]

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
                        target_address = 0x0000 + pc

                        opcode = opcode_to_binary[instruction]

                        binary = f'{opcode}{pc:011b}'

                        hexcode = binary_to_hex(binary)
                        ra_address=base_address+2
                        register_values['$ra'] = ra_address
                        # self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}     Jump: {hex(target_address)}   \n")
                        
                        self.reg_text.insert("end", f"$zero            0             {format_hex(register_values['$zero'])} \n")
                        self.reg_text.insert("end", f"$t0              1             {format_hex(register_values['$t0'])}\n")
                        self.reg_text.insert("end", f"$t1              2             {format_hex(register_values['$t1'])}\n")
                        self.reg_text.insert("end", f"$t2              3             {format_hex(register_values['$t2'])}\n")
                        self.reg_text.insert("end", f"$s0              4             {format_hex(register_values['$s0'])}\n")
                        self.reg_text.insert("end", f"$s1              5             {format_hex(register_values['$s1'])}\n")
                        self.reg_text.insert("end", f"$sp              6             {format_hex(register_values['$sp'])}\n")
                        self.reg_text.insert("end", f"$ra              7             {format_hex(register_values['$ra'])}\n")
                        self.reg_text.insert("end", f"————————————————————————————————————————\n")

                        self.memory_text.insert("end", f"Memory Address: 0x000010   Data: {read_memory(0x000010)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000012   Data: {read_memory(0x000012)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000014   Data: {read_memory(0x000014)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000016   Data: {read_memory(0x000016)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000018   Data: {read_memory(0x000018)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x00001a   Data: {read_memory(0x00001a)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x00001c   Data: {read_memory(0x00001c)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x00001e   Data: {read_memory(0x00001e)}\n")
                        self.memory_text.insert("end", f"————————————————————————————————————————\n")    
                        #self.reg_text.insert("end", f"Name:$ra---Number:31----Value:{format_hex(ra_address)}\n")
                        # base_address += 2
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

                        pc = line_number * 2
                        target_address = 0x0000 + pc

                        opcode = opcode_to_binary[instruction]

                        binary = f'{opcode}{pc:011b}'

                        hexcode = binary_to_hex(binary)

                        self.reg_text.insert("end", f"$zero            0             {format_hex(register_values['$zero'])} \n")
                        self.reg_text.insert("end", f"$t0              1             {format_hex(register_values['$t0'])}\n")
                        self.reg_text.insert("end", f"$t1              2             {format_hex(register_values['$t1'])}\n")
                        self.reg_text.insert("end", f"$t2              3             {format_hex(register_values['$t2'])}\n")
                        self.reg_text.insert("end", f"$s0              4             {format_hex(register_values['$s0'])}\n")
                        self.reg_text.insert("end", f"$s1              5             {format_hex(register_values['$s1'])}\n")
                        self.reg_text.insert("end", f"$sp              6             {format_hex(register_values['$sp'])}\n")
                        self.reg_text.insert("end", f"$ra              7             {format_hex(register_values['$ra'])}\n")
                        self.reg_text.insert("end", f"————————————————————————————————————————\n")

                        self.memory_text.insert("end", f"Memory Address: 0x000010   Data: {read_memory(0x000010)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000012   Data: {read_memory(0x000012)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000014   Data: {read_memory(0x000014)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000016   Data: {read_memory(0x000016)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x000018   Data: {read_memory(0x000018)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x00001a   Data: {read_memory(0x00001a)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x00001c   Data: {read_memory(0x00001c)}\n")
                        self.memory_text.insert("end", f"Memory Address: 0x00001e   Data: {read_memory(0x00001e)}\n")
                        self.memory_text.insert("end", f"————————————————————————————————————————\n") 

                        # self.output_text.insert("end", f"Address: {hex(base_address)}        HexCode: {hexcode}        MachineCode: {binary}       Basic: {line}     Jump: {hex(target_address)}   \n")
                        # base_address += 2
                        words = []
                        continue
                        
            if direction[k] != -1:
                current_line = direction[k]
                #print(f"CurrentLine yani siradaki: {current_line}")
                continue
            # current_line+=1
            # k+=1

    def __init__(self):

        self.line_adim_index=0
        self.reg_adim_index=0
        self.pointer_adim_index=0

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

        
        frame = tk.Frame(self.window)
        frame.pack(side="top")

        
        self.reset_button = tk.Button(frame, text="Run Code", command=self.result_code, font=("Arial", 12), background="#7392fe", padx=10, pady=5)
        self.reset_button.pack(side="left", padx=20, pady=10)

        self.run_button = tk.Button(frame, text="Detailed Run Code", command=self.run_code, font=("Arial", 12), background="#7392fe", padx=10, pady=5)
        self.run_button.pack(side="left", padx=20, pady=10)

        self.adim_button = tk.Button(frame, text="Step", command=self.adim_code, font=("Arial", 12), background="#7392fe", padx=10, pady=5)
        self.adim_button.pack(side="left", padx=20, pady=10)

        self.reset_button = tk.Button(frame, text="Reset", command=self.reset_code, font=("Arial", 12), background="#7392fe", padx=10, pady=5)
        self.reset_button.pack(side="left", padx=20, pady=10)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Custom.TFrame", background="#6A46FA")
        style.configure("Custom.TLabel",   font=("Arial", 18, "bold") )

        self.main_frame = ttk.Frame(self.window, style="Custom.TFrame")
        self.main_frame.pack(padx=25, pady=25)

        self.register_frame = ttk.Frame(self.main_frame, width=750, style="Custom.TLabel")
        self.register_frame.pack(side="right", padx=10, pady=10)
        self.create_register_widgets()

        self.reg_text.insert("end", f"$zero            0             0x000000 \n")
        self.reg_text.insert("end", f"$t0              1             0x000000 \n")
        self.reg_text.insert("end", f"$t1              2             0x000000 \n")
        self.reg_text.insert("end", f"$t2              3             0x000000 \n")
        self.reg_text.insert("end", f"$s0              4             0x000000 \n")
        self.reg_text.insert("end", f"$s1              5             0x000000 \n")
        self.reg_text.insert("end", f"$sp              6             0x000000 \n")
        self.reg_text.insert("end", f"$ra              7             0x000000 \n")
        self.reg_text.insert("end", f"————————————————————————————————————————\n") 

        self.message_frame = ttk.Frame(self.main_frame, width=375, style="Custom.TLabel")
        self.message_frame.pack(side="bottom", padx=10, pady=10)
        self.create_message_widgets()   

        self.memory_frame = ttk.Frame(self.main_frame, width=375, style="Custom.TLabel")
        self.memory_frame.pack(side="bottom", padx=10, pady=10)
        self.create_memory_widgets()

        # self.pointer_frame = ttk.Frame(self.main_frame, width=375)
        # self.pointer_frame.pack(side="left", padx=10, pady=10)
        # self.create_pointer_widgets()

        self.code_frame = ttk.Frame(self.main_frame, width=750, style="Custom.TLabel")
        self.code_frame.pack(side="left", padx=10, pady=10)
        self.create_code_widgets()

        # self.pointer2_frame = ttk.Frame(self.main_frame, width=375)
        # self.pointer2_frame.pack(side="left", padx=0, pady=0)
        # self.create_pointer2_widgets()

        self.output_frame = ttk.Frame(self.main_frame, width=750, style="Custom.TLabel")
        self.output_frame.pack(side="bottom", padx=10, pady=10)
        self.create_output_widgets()

        self.window.mainloop()

    def create_register_widgets(self):
        register_label = ttk.Label(self.register_frame, text="Name                                  Number                                  Value")
        register_label.pack(padx=5, pady=5)

        self.reg_text = tk.Text(self.register_frame, height=130, width=40)
        self.reg_text.pack(padx=2, pady=2)

    def create_memory_widgets(self):
        memory_label = ttk.Label(self.memory_frame, text="Memory")
        memory_label.pack(padx=2, pady=5)

        self.memory_text = tk.Text(self.memory_frame, height=10, width=150)
        self.memory_text.pack(padx=5, pady=2)

    def create_message_widgets(self):
        message_label = ttk.Label(self.message_frame, text="Message")
        message_label.pack(padx=2, pady=5)

        self.message_text = tk.Text(self.message_frame, height=5, width=150)
        self.message_text.pack(padx=5, pady=4)

    # def create_pointer_widgets(self):
    #     pointer_label = ttk.Label(self.pointer_frame, text="Pointer")
    #     pointer_label.pack(padx=2, pady=5)

    #     self.pointer_text = tk.Text(self.pointer_frame, height=60, width=5)
    #     self.pointer_text.pack(padx=5, pady=2)

    # def create_pointer2_widgets(self):
    #     pointer2_label = ttk.Label(self.pointer2_frame, text="")
    #     pointer2_label.pack(padx=2, pady=5)

    #     self.pointer2_text = tk.Text(self.pointer2_frame, height=0, width=0)
    #     self.pointer2_text.pack(padx=5, pady=2)

    def create_code_widgets(self):
        code_label = ttk.Label(self.code_frame, text="Code")
        code_label.pack(padx=2, pady=5)

        self.code_text = tk.Text(self.code_frame, height=30, width=25)
        self.code_text.pack(padx=2, pady=2)

    def create_output_widgets(self):
        output_label = ttk.Label(self.output_frame, text="Address                                                                    HexCode                                                           MachineCode                                                            Basic")
        output_label.pack(padx=2, pady=5)

        self.output_text = tk.Text(self.output_frame, height=30, width=110)
        self.output_text.pack(padx=5, pady=2)


if __name__ == "__main__":
    app = App()


