#!/usr/bin/env python
import sys
import binascii
import struct

MAGIC_64 = b'\x00\x00\x08\x00\xC0\xFF\xFF\xFF\x40\x00\x08\x00\xC0\xFF\xFF\xFF'
ZERO_64	= b'\x00\x00\x00\x00\x00\x00\x00\x00'

class SymsFinder:
    def __init__(self, image_path, is_64 = True):
        self._image_path = image_path
        self._offset = 0
        if is_64:
            self._align = 8
        else:
            self._align = 4
        self._kallsyms = []

        self._kallsyms_addresses = 0
        self._kallsyms_num_syms = 0
        self._kallsyms_token_index = 0
        self._kallsym_token_tables = 0
        self._kallsyms_names = 0

    def _read_image(self):
        with open(self._image_path, 'rb') as fp:
            self._image_content = bytearray(fp.read())
    def _find_syms_info(self):
        self._kallsyms_addresses = self._image_content.find(MAGIC_64)
        if self._kallsyms_addresses == -1:
            return
        print('[*] Find kallsyms_addresses offset: 0x%x' % self._kallsyms_addresses)
        self._offset = self._kallsyms_addresses

        while True:
            kallsyms_num_syms = struct.unpack_from("<Q", self._image_content, self._offset)[0]
            if kallsyms_num_syms != 0 and kallsyms_num_syms & 0xFFFFFF0000000000 == 0:
                break
            self._offset += self._align
        self._kallsyms_num_syms = kallsyms_num_syms
        print('[*] Numuber of syms: %d' % self._kallsyms_num_syms)

        self._offset += self._align
        while True:
            kallsyms_names = struct.unpack_from("<Q", self._image_content, self._offset)[0]
            if kallsyms_names != 0:
                break
            self._offset += self._align
        self._kallsyms_names = self._offset
        print('[*] Find kallsyms_names offset: 0x%x' % self._kallsyms_names)

        self._offset = self._image_content.find(ZERO_64, self._offset)
        self._offset = (self._offset  +self._align - 1)& ~(self._align -1)
        while True:
            kallsyms_markers = struct.unpack_from("<Q", self._image_content, self._offset)[0]
            if kallsyms_markers != 0:
                break
            self._offset += self._align
        self._kallsyms_markers  = self._offset
        print('[*] Find kallsyms_markers offset: 0x%x' % self._kallsyms_markers)

        self._offset = self._image_content.find(ZERO_64, self._offset)
        self._offset = (self._offset + self._align - 1)& ~(self._align -1)
        while True:
            kallsym_token_tables = struct.unpack_from("<Q", self._image_content, self._offset)[0]
            if kallsym_token_tables != 0:
                break
            self._offset += self._align
        self._kallsym_token_tables = self._offset
        print('[*] Find kallsym_token_tables offset: 0x%x' % self._kallsym_token_tables)

        self._offset = self._image_content.find(ZERO_64, self._offset)
        self._offset = (self._offset + self._align - 1)& ~(self._align -1)
        while True:
            kallsyms_token_index = struct.unpack_from("<Q", self._image_content, self._offset)[0]
            if kallsyms_token_index != 0:
                break
            self._offset += self._align
        self._kallsyms_token_index = self._offset
        print('[*] Find kallsyms_token_index offset: 0x%x' % self._kallsyms_token_index)

    def _find_syms(self):
        off = 0
        for i in range(self._kallsyms_num_syms):
            sym_name = ''
            s_type = ''

            name_len = struct.unpack_from("B", self._image_content, self._kallsyms_names + off)[0]
            index_infos = struct.unpack_from("%ds"%name_len, self._image_content, self._kallsyms_names + off + 1)[0]
            for index in index_infos:
                token_index = struct.unpack_from("H", self._image_content, self._kallsyms_token_index + ord(index)*2)[0]
                k=0
                while True:
                    name = struct.unpack_from("B", self._image_content, self._kallsym_token_tables+token_index + k)[0]
                    if name == 0:
                        break
                    if not s_type:
                        s_type = chr(name)
                    else:
                        sym_name += chr(name)
                    k += 1
            self._kallsyms.append([sym_name, s_type, self._get_address(i)])
            off = off + name_len + 1

    def _get_address(self, index):
        return struct.unpack_from("<Q", self._image_content, self._kallsyms_addresses + index * self._align)[0]

    def parse_syms(self):
        self._read_image()
        if not self._image_content:
            return
        self._find_syms_info()

        if self._kallsyms_addresses == 0:
            print('[-] kallsyms_addresses is null')
            return
        if self._kallsyms_num_syms == 0:
            print('[-] kallsyms_num_syms is null')
            return
        if self._kallsyms_token_index == 0:
            print('[-] kallsyms_token_index is null')
            return
        if self._kallsym_token_tables == 0:
            print('[-] kallsym_token_tables is null')
            return
        if self._kallsyms_names == 0:
            print('[-] kallsyms_names is null')
            return
        self._find_syms()
        return self._kallsyms

if __name__ == '__main__':
    finder = SymsFinder(sys.argv[1])
    for i in finder.parse_syms():
        print('0x%x %s %s' %(i[2],i[1],i[0]))
