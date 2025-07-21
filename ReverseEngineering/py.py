from elftools.elf.elffile import ELFFile 
from elftools.elf.sections import Section
import json
import os
import sys

def fetch_file_info(file_path='chall'):
    file_info = {}
    file_info['FILE_SIZE'] = os.path.getsize(file_path) 
    with open(file_path, 'rb') as f:
        elf = ELFFile(f)
        head = elf.header
        #file_info['ELF_CLASS'] = elf.elfclass 
        file_info['ELF_CLASS'] = (head['e_ident']['EI_CLASS'])
        
        if head['e_ident']['EI_DATA'] == 'ELFDATA2LSB':
            file_info['ENDIANNESS'] = 'LITTLE_ ENDIAN'
        elif head['e_ident']['EI_DATA'] == 'ELFDATA2MSB':
            file_info['ENDIANNESS'] = 'BIG_ ENDIAN'
        else:
            sys.exit('Endiannes unknown')
        print('Section shit:')
        #for section in elf.iter_sections():
            #print(section.name)
        section_headers = {}

        for section in elf.iter_sections():
            name = section.name or f"<unnamed_{section.header['sh_name']}>"
            section_headers[name] = dict(section.header)
        
        # Check PIE
        e_type = head['e_type']
        pie = (e_type == 'ET_DYN')
        file_info['PIE'] =  'PIE_ENABLED' if e_type == 'ET_DYN' else 'NO_PIE'

        # Check NX
        has_gnu_stack = False
        nx_enabled = False
        for segment in elf.iter_segments():
            if segment.header.p_type == 'PT_GNU_STACK':
                has_gnu_stack = True
                # If execute bit is not set, NX is enabled
                nx_enabled = not bool(segment.header.p_flags & 0x1)  # PF_X
                break
        file_info['NX'] = 'NX_ENABLED' if nx_enabled else 'NO_NX'

        # Check RELRO
        has_gnu_relro = False
        partial_relro = False
        full_relro = False
        for segment in elf.iter_segments():
            if segment.header.p_type == 'PT_GNU_RELRO':
                has_gnu_relro = True
        dynsec = elf.get_section_by_name('.dynamic')
        if dynsec:
            for tag in dynsec.iter_tags():
                if tag.entry.d_tag == 'DT_BIND_NOW':
                    full_relro = True
        if has_gnu_relro:
            partial_relro = True
        if full_relro:
            relro = 'FULL_RELRO'
        elif partial_relro:
            relro = 'PARTIAL_RELRO'
        else:
            relro = 'NO_RELRO'
        
        file_info['RELRO'] = relro

        # Print result
        print(f"PIE: {'Yes' if pie else 'No'}")
        print(f"NX: {'Enabled' if nx_enabled else 'Disabled'}")
        print(f"RELRO: {relro}")


        file_info['SECTION_HEADERS'] = section_headers
    print('header: \n', head)

    #print(json.dumps(file_info, indent=2))
    #print('What I should return, \n', file_info)
    with open("output.json", "w") as f:
        json.dump(file_info, f, indent = 4)

fetch_file_info()
