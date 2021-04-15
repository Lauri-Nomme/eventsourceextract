import struct

import pefile


def parse_messages(data):
    number_of_blocks = struct.unpack("<I", data[0:4])[0]
    block_start = 4
    for block_idx in range(number_of_blocks):
        low_id = struct.unpack("<I", data[block_start:block_start + 4])[0]
        high_id = struct.unpack("<I", data[block_start + 4:block_start + 8])[0]
        offset_to_entries = struct.unpack("<I", data[block_start + 8:block_start + 12])[0]

        entry_offset = offset_to_entries
        for message_id in range(low_id, high_id + 1):
            length = struct.unpack("<h", data[entry_offset:entry_offset + 2])[0]
            flags = struct.unpack("<h", data[entry_offset + 2:entry_offset + 4])[0]

            if flags == 1:
                value = data[entry_offset + 4:entry_offset + length].decode('utf-16le').rstrip('\0')
                yield message_id, value
            elif flags == 0:
                value = data[entry_offset + 4:entry_offset + length].decode('ascii').rstrip('\0')
                yield message_id, value

            entry_offset += length

        block_start += 4 * 3


def get_message_table(pe, id, lang_id):
    for message_table in (e for e in pe.DIRECTORY_ENTRY_RESOURCE.entries if e.id == pefile.RESOURCE_TYPE['RT_MESSAGETABLE']):
        for dir_0 in (d for d in message_table.directory.entries if d.id == id):
            for dir_1 in (d for d in dir_0.directory.entries if d.id == lang_id):
                yield dir_1.data


def pe_messages(filename):
    pe = pefile.PE(filename)
    for message_table in get_message_table(pe, 1, 1033):
        data = pe.get_data(message_table.struct.OffsetToData, message_table.struct.Size)
        for message in parse_messages(data):
            yield message
