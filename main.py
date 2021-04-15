import winreg
from os import path
from winreg import *

import jsonstreams

from messagetable import pe_messages


def subkeys(key):
    subkey_count = QueryInfoKey(key)[0]
    for subkey_idx in range(subkey_count):
        yield EnumKey(key, subkey_idx)


def value(key, name):
    try:
        value = QueryValueEx(key, name)
        return value[0]
    except WindowsError:
        return None


def process_sources(outfile):
    files = set()
    with jsonstreams.Stream(jsonstreams.Type.OBJECT, filename=outfile, pretty=True, indent=2) as sources_stream:
        with ConnectRegistry(None, HKEY_LOCAL_MACHINE) as hive:
            with OpenKey(hive, r"SYSTEM\CurrentControlSet\Services\EventLog", 0, KEY_READ) as event_log_key:
                for log in subkeys(event_log_key):
                    with sources_stream.subobject(log) as log_stream:
                        with OpenKey(event_log_key, log) as log_key:
                            for source in subkeys(log_key):
                                with log_stream.subobject(source) as source_stream:
                                    with OpenKey(log_key, source) as source_key:
                                        event_message_file = value(source_key, "EventMessageFile")
                                        category_message_file = value(source_key, "CategoryMessageFile")
                                        category_count = value(source_key, "CategoryCount")
                                        parameter_message_file = value(source_key, "ParameterMessageFile")

                                        if category_count:
                                            source_stream.write('category_count', category_count)

                                        if event_message_file:
                                            with source_stream.subarray('event_messages') as event_messages_stream:
                                                for zz in event_message_file.split(';'):
                                                    zz = winreg.ExpandEnvironmentStrings(zz)
                                                    event_messages_stream.write(zz)
                                                    files.add(zz)

                                        if category_message_file:
                                            with source_stream.subarray('category_messages') as category_messages_stream:
                                                for zz in category_message_file.split(';'):
                                                    zz = winreg.ExpandEnvironmentStrings(zz)
                                                    category_messages_stream.write(zz)
                                                    files.add(zz)

                                        if parameter_message_file:
                                            with source_stream.subarray('parameter_messages') as parameter_messages_stream:
                                                for zz in parameter_message_file.split(';'):
                                                    zz = winreg.ExpandEnvironmentStrings(zz)
                                                    parameter_messages_stream.write(zz)
                                                    files.add(zz)
    return files


def extract_messages(filename, target_stream):
    for message in pe_messages(filename):
        event_id, value = message
        target_stream.write("%s" % event_id, value)


files = process_sources('sources.json')

with jsonstreams.Stream(jsonstreams.Type.OBJECT, filename='messages.json', pretty=True, indent=2) as sources_stream:
    files_count = len(files)
    for idx, source_file in enumerate(files):
        with sources_stream.subobject(source_file) as source_stream:
            mui_file = path.join(path.dirname(source_file), 'en-US', path.basename(source_file) + '.mui')
            for file in [mui_file, source_file]:
                print("[%s/%s] %s" % (idx, files_count, file))
                if path.exists(file):
                    for message in pe_messages(file):
                        event_id, value = message
                        source_stream.write("%s" % event_id, value)
                    break
