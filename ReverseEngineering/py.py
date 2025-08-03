from elftools.elf.elffile import ELFFile 
from elftools.elf.sections import SymbolTableSection
import json
import os
import sys
def fetch_file_info(file_path):
    file_info = {}
    file_info['FILE_SIZE'] = os.path.getsize(file_path) 
    with open(file_path, 'rb') as f:
        elf = ELFFile(f)
        head = elf.header # Header file

        file_info['ELF_CLASS'] = (head['e_ident']['EI_CLASS']) # 32/64/none
        
        # Endianness 
        if head['e_ident']['EI_DATA'] == 'ELFDATA2LSB':
            file_info['ENDIANNESS'] = 'LITTLE_ ENDIAN'
        elif head['e_ident']['EI_DATA'] == 'ELFDATA2MSB':
            file_info['ENDIANNESS'] = 'BIG_ ENDIAN'
        else:
            sys.exit('Endiannes unknown')
        
        # Version
        file_info["VERSION"] = 'CURRENT_VERSION' if head['e_version'] == 'EV_CURRENT' else 'INVALID_VERSION'
       
        # Section header

        section_headers = {}
        for section in elf.iter_sections():
            name = section.name or f"<unnamed_{section.header['sh_name']}>"
            section_headers[name] = dict(section.header)
        file_info['SECTION_HEADERS'] = section_headers
        
        # Security bit check (PIE, NX, RELRO)
        # PIE
        e_type = head['e_type']
        pie = (e_type == 'ET_DYN')
        file_info['PIE'] =  'PIE_ENABLED' if e_type == 'ET_DYN' else 'NO_PIE'

        # NX, RELRO 
        nx = "NO_NX"
        some_relro = False # Some form of RELRO (partial/full)

        for segment in elf.iter_segments():
            if segment.header.p_type == 'PT_GNU_STACK':
                if segment.header.p_flags & 0x1:
                    nx = "NO_NX"
                else:
                    nx = "NX_ENABLED"
                nx_enabled = not bool(segment.header.p_flags & 0x1)  # PF_X
                break
            if segment.header.p_type == 'PT_GNU_RELRO':
                some_relro = True # This means that atleast partial relro is enabled 
                relro = "NO_RELRO"
        file_info['NX'] = nx

        # Furthur confirming RELRO (parital/full)
        dynsec = elf.get_section_by_name('.dynamic')
        if dynsec:
            for tag in dynsec.iter_tags():
                if tag.entry.d_tag == 'DT_BIND_NOW':
                     relro = "FULL_RELRO"
                else:
                    relro = "PARTIAL_RELRO"
        file_info['RELRO'] = relro

        
    with open("output.json", "w") as f:
        json.dump(file_info, f, indent = 4)

# Extracts symbol table information
def extract_symbol_table(file_path):
    symbol_list = {}
    with open(file_path, 'rb') as f:
        elf = ELFFile(f)
        for section in elf.iter_sections(): # Iterating through each section
            if isinstance(section, SymbolTableSection): # Checking for symbol table section
                section_name = section.name
                if section_name not in symbol_list: # New List for each symbol type
                    symbol_list[section_name] = []

                for symbol in section.iter_symbols(): # Iterating through each symbol in the table
                    symbol_info = { 
                        'name': symbol.name,
                        'bind': symbol['st_info']['bind'],
                        'type': symbol['st_info']['type'],
                        'shndx': symbol['st_shndx'],
                        'value': symbol['st_value'],
                        'size': symbol['st_size']
                    } # Collecting symbol info  
                    symbol_list[section_name].append(symbol_info)
    symbol_table = {"SYMBOLS": symbol_list}

    with open("symbols.json", "w") as f:
        json.dump(symbol_table, f, indent=4)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Incorrect amount of arguments entered")
        sys.exit()

    file_path = sys.argv[1]
    arg = sys.argv[2]

    if arg == "--h":
        fetch_file_info(file_path)
    elif arg == "--s":
        extract_symbol_table(file_path)
    else:
        print(f"Unknown argument: {arg}")
        sys.exit()
