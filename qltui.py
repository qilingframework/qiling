import os
import ast
import pickle
import re
import six
import argparse
from json2html import *
import pdfkit
from pyfx import Controller
import json
from pprint import pprint
from pyfx.model import DataSourceType
from datetime import datetime

import questionary
from questionary import Validator, ValidationError, prompt
try:
    from termcolor import colored
except ImportError:
    colored = None


from qiling.const import os_map, arch_map, verbose_map
from qiling.extensions.coverage import utils as cov_utils

motd = """
    ██████     ███  ████   ███                     
  ███░░░░███  ░░░  ░░███  ░░░                      
 ███    ░░███ ████  ░███  ████  ████████    ███████
░███     ░███░░███  ░███ ░░███ ░░███░░███  ███░░███
░███   ██░███ ░███  ░███  ░███  ░███ ░███ ░███ ░███
░░███ ░░████  ░███  ░███  ░███  ░███ ░███ ░███ ░███
 ░░░██████░██ █████ █████ █████ ████ █████░░███████
   ░░░░░░ ░░ ░░░░░ ░░░░░ ░░░░░ ░░░░ ░░░░░  ░░░░░███
                                           ███ ░███
                                          ░░██████ 
                                           ░░░░░░
"""

ERROR_COLOR = "red"

HEADING_COLOR = "green"

OUTPUT_COLOR = "blue"

TITLE_COLOR = "blue"

prog = os.path.basename(__file__)

HEX_REGEX = r'^(0[xX])[a-fA-F0-9]+$'


class Callback_Functions():
    """
    Callback Functions for Hook Operation
    """

    @staticmethod
    def read_mem_2(ql, user_data):
        buff = ql.mem.read(user_data["address"], user_data["bytes_size"])
        ql.log.info(f"Hook was triggered at -> {user_data['address']}")
        ql.log.info(buff)

    @staticmethod
    def read_mem_4(ql, address=0, size=0, user_data=None):
        buff = ql.mem.read(user_data["address"], user_data["bytes_size"])
        ql.log.info(f"Hook was triggered at -> {user_data['address']}")
        ql.log.info(buff)

    @staticmethod
    def read_mem_6(ql, address=0, size=0, access=1, value=0, user_data=None):
        buff = ql.mem.read(user_data["address"], user_data["bytes_size"])
        ql.log.info(f"Hook was triggered at -> {user_data['address']}")
        ql.log.info(buff)

    @staticmethod
    def read_reg_2(ql,user_data):
        buff = ql.reg.read(user_data["register_name"])
        ql.log.info(f"Hook was triggered at -> {user_data['register_name']}")
        ql.log.info(buff)

    @staticmethod
    def read_reg_4(ql, address=0, size=0, user_data=None):
        buff = ql.reg.read(user_data["register_name"])
        ql.log.info(f"Hook was triggered at -> {user_data['register_name']}")
        ql.log.info(buff)

    @staticmethod
    def read_reg_6(ql, address=0, size=0, access=1, value=0, user_data=None):
        buff = ql.reg.read(user_data["register_name"])
        ql.log.info(f"Hook was triggered at -> {user_data['register_name']}")
        ql.log.info(buff)

    @staticmethod
    def write_mem_2(ql, user_data):
        buff = ql.mem.write(user_data["address"], user_data["value"])
        ql.log.info(f"Hook was triggered at -> {user_data['address']}")
        ql.log.info(buff)

    @staticmethod
    def write_mem_4(ql, address=0, size=0, user_data=None):
        buff = ql.mem.write(user_data["address"], user_data["value"])
        ql.log.info(f"Hook was triggered at -> {user_data['address']}")
        ql.log.info(buff)

    @staticmethod
    def write_mem_6(ql, address=0, size=0, access=1, value=0, user_data=None):
        buff = ql.mem.write(user_data["address"], user_data["value"])
        ql.log.info(f"Hook was triggered at -> {user_data['address']}")
        ql.log.info(buff)

    @staticmethod
    def write_reg_2(ql,user_data):
        buff = ql.reg.write(user_data["register_name"], user_data["value"])
        ql.log.info(f"Hook was triggered at -> {user_data['register_name']}")
        ql.log.info(buff)

    @staticmethod
    def write_reg_4(ql, address=0, size=0, user_data=None):
        buff = ql.reg.write(user_data["register_name"], user_data["value"])
        ql.log.info(f"Hook was triggered at -> {user_data['register_name']}")
        ql.log.info(buff)

    @staticmethod
    def write_reg_6(ql, address=0, size=0, access=1, value=0, user_data=None):
        buff = ql.reg.write(user_data["register_name"], user_data["value"])
        ql.log.info(f"Hook was triggered at -> {user_data['register_name']}")
        ql.log.info(buff)

    @staticmethod
    def emu_start_2(ql, user_data):
        ql.emu_start(begin=user_data["start"], end=user_data["end"])

    @staticmethod
    def emu_start_4(ql, address=0, size=0, user_data=None):
        ql.emu_start(begin=user_data["start"], end=user_data["end"])

    @staticmethod
    def emu_start_6(ql, address=0, size=0, access=1, value=0, user_data=None):
        ql.emu_start(begin=user_data["start"], end=user_data["end"])

    @staticmethod
    def emu_stop_2(ql, user_data=None):
        ql.log.info('killer switch found, stopping')
        ql.emu_stop()

    @staticmethod
    def emu_stop_4(ql, address=0, size=0, user_data=None):
        ql.log.info('killer switch found, stopping')
        ql.emu_stop()

    @staticmethod
    def emu_stop_6(ql, address=0, size=0, access=1, value=0, user_data=None):
        ql.log.info('killer switch found, stopping')
        ql.emu_stop()

    @staticmethod
    def save_2(ql, user_data=None):
        ql.save()

    @staticmethod
    def save_4(ql, address=0, size=0, user_data=None):
        ql.save()

    @staticmethod
    def save_6(ql, address=0, size=0, access=1, value=0, user_data=None):
        ql.save()

def env_arg(value):
    """
    Function to read env parameter
    """
    if value == "{}":
        return {}
    else:
        if os.path.exists(value):
            with open(value, 'rb') as f:
                env = pickle.load(f)
        else:
            env = ast.literal_eval(value)
        return env


def verbose_arg(value):
    """
    Function to map Verbose
    """
    return verbose_map[value]


def read_file(fname: str):
    """
    Function to read code from file
    """
    with open(fname, "rb") as f:
        content = f.read()

    return content


def log(string, color):
    """
    Function to beautify terminal output
    """
    if colored:
        six.print_(colored(string, color))
    else:
        six.print_(string)


class PdfConverter(object):
    """
    Pdf Converter object
    """

    def __init__(self):
        pass

    def to_html(self, json_doc):
        return json2html.convert(json=json_doc)

    def to_pdf(self, html_str):
        return pdfkit.from_string(html_str, None)


class IntValidator(Validator):
    """
    Integer validator
    """
    def validate(self, value):
        try:
            int(value.text)
            return True
        except:
            raise ValidationError(
                message="Integer required",
                cursor_position=len(value.text))


class HexValidator(Validator):
    """
    Hex validator
    """
    def validate(self, value):
        if re.match(HEX_REGEX, value.text):
            return True
        else:
            raise ValidationError(
                message="Address required",
                cursor_position=len(value.text))


class IntHexValidator(Validator):
    """
    Integer/Hex validator
    """
    def validate(self, value):
        if re.match(HEX_REGEX, str(value.text)):
            return True
        else:
            try:
                int(value.text)
                return True
            except:
                raise ValidationError(
                    message="Integer or Hex required",
                    cursor_position=len(value.text))

class DirectoryPathValidator(Validator):
    """
    Required Directory Path validator
    """
    def validate(self, value):
        if len(value.text):
            if os.path.isdir(value.text):
                return True
            else:
                raise ValidationError(
                    message="Directory not found",
                    cursor_position=len(value.text))
        else:
            return True


class RequiredDirectoryPathValidator(Validator):
    """
    Directory Path validator
    """
    def validate(self, value):
        if len(value.text):
            if os.path.isdir(value.text):
                return True
            else:
                raise ValidationError(
                    message="Directory not found",
                    cursor_position=len(value.text))
        else:
            raise ValidationError(
                message="You can't leave this blank",
                cursor_position=len(value.text))


class FilePathValidator(Validator):
    """
    File Path validator
    """
    def validate(self, value):
        if len(value.text):
            if os.path.isfile(value.text):
                return True
            else:
                raise ValidationError(
                    message="File not found",
                    cursor_position=len(value.text))
        else:
            return True


class ENVFilePathValidator(Validator):
    """
    File Path validator for env parameter
    """
    def validate(self, value):
        if value.text == "{}":
            return True
        if len(value.text):
            if os.path.isfile(value.text):
                return True
            else:
                raise ValidationError(
                    message="File not found",
                    cursor_position=len(value.text))
        else:
            return True


def ask_option():
    """
    Ask for operation(run/code)
    """
    answer = questionary.select(
     "Select an Option:",
     choices=['Run', 'Code']).ask()

    return answer.lower()


def ask_run_options():
    """
    Ask arguments for run
    """
    filename = questionary.path("filename:", validate=FilePathValidator).ask()
    
    rootfs = questionary.path("rootfs:", only_directories=True,
        validate=RequiredDirectoryPathValidator).ask()
    
    args = questionary.text("args:").ask()
    args = args.split()
    
    run_args = questionary.text("run_args:").ask()
    run_args = run_args.split()

    return {"filename": filename, "rootfs": rootfs, "args": args,
            "run_args": run_args}


def ask_code_options():
    """
    Ask arguments for code
    """
    filename = questionary.path("filename:", validate=FilePathValidator).ask()
    
    input_ = questionary.text("input:").ask()
    if not input_:
        input_ = None
    
    format_ = questionary.select(
     "format:",
     choices=['bin', 'asm', 'hex']).ask()
    
    arch = questionary.select(
     "arch:",
     choices=arch_map).ask()
    
    endian = questionary.select(
     "endian:",
     choices=['little', 'big']).ask()
    
    os = questionary.select(
     "os:",
     choices=os_map).ask()
    
    rootfs = questionary.path("rootfs:", only_directories=True,
        validate=RequiredDirectoryPathValidator, default=".").ask()
    
    thumb = questionary.confirm("thumb:",
        default=False, auto_enter=True).ask()
    
    return {"filename": filename, "input": input_, "format": format_,
            "arch": arch, "endian": endian, "os": os, "rootfs": rootfs,
            "thumb": thumb}


def ask_additional_options():
    """
    Ask additional options for run/code
    """
    verbose = questionary.select(
     "verbose:",
     choices=list(verbose_map.keys()),
     default="default").ask()
    verbose = verbose_arg(verbose)

    env = questionary.path("env:", default="{}", validate=ENVFilePathValidator).ask()
    env = env_arg(env)

    gdb = questionary.text("gdb:").ask()
    if not gdb:
        gdb = None

    qdb = questionary.confirm("qdb:",
        default=False, auto_enter=True).ask()

    rr = questionary.confirm("rr:",
        default=False, auto_enter=True).ask()

    profile = questionary.text("profile:").ask()
    if not profile:
        profile = None

    console = questionary.confirm("console:",
        default=True, auto_enter=True).ask()

    filter_ = questionary.text("filter:").ask()
    if not filter_:
        filter_ = None

    log_file = questionary.path("log-file:", validate=FilePathValidator).ask()
    if not log_file:
        log_file = None
    
    log_plain = questionary.confirm("log-plain:",
        default=False, auto_enter=True).ask()
    
    root = questionary.confirm("root:",
        default=False, auto_enter=True).ask()
    
    debug_stop = questionary.confirm("debug-stop:",
        default=False, auto_enter=True).ask()
    
    multithread = questionary.confirm("multithread:",
        default=False, auto_enter=True).ask()
    
    timeout = int(questionary.text("profile:", default="0", validate=IntValidator).ask())
    
    coverage_file = questionary.path("coverage-file:", validate=FilePathValidator).ask()
    if not coverage_file:
        coverage_file = None
    
    coverage_format = questionary.select(
     "coverage-format:",
     choices=list(cov_utils.factory.formats),
     default="drcov").ask()
    
    json_ = questionary.confirm("json:",
        default=False, auto_enter=True).ask()
    
    libcache = questionary.confirm("libcache:",
        default=False, auto_enter=True).ask()

    return {"verbose": verbose, "env": env, "gdb": gdb, "qdb": qdb,
            "rr": rr, "profile": profile, "console": console,
            "filter": filter_, "log_file": log_file,
            "log_plain": log_plain, "root": root, "debug_stop": debug_stop,
            "multithread": multithread, "timeout": timeout,
            "coverage_file": coverage_file, "coverage_format": coverage_format,
            "json": json_, "libcache": libcache}
    

def get_data():
    """
    Main Qltui function
    """
    print(motd)
    log("Welcome to Qiling", HEADING_COLOR)
    log("Cross Platform and Multi Architecture Advanced Binary Emulation Framework", HEADING_COLOR)

    command = ask_option()

    if command == 'run':
        log("Select Run Options", OUTPUT_COLOR)
        command_options = ask_run_options()

        log("Select Additional Options", OUTPUT_COLOR)
        additional_options = ask_additional_options()

    elif command == 'code':
        log("Select Code Options", OUTPUT_COLOR)
        command_options = ask_code_options()

        log("Select Additional Options", OUTPUT_COLOR)
        additional_options = ask_additional_options()

    else:
        log("Error", ERROR_COLOR)

    options = command_options | additional_options
    options['subcommand'] = command

    namespace = argparse.Namespace(**options)

    return namespace


def ask_report():
    """
    Ask for the format of report
    """
    answer = questionary.select(
     "Select an Option:",
     choices=['Report', 'Interactive Report', 'Report to PDF', 'Quit']).ask()

    return answer.lower()


def show_report(ql, report, hook_dictionary):
    """
    Ask if user wants to see the report
    """
    log("Report", HEADING_COLOR)

    os_map_reverse = dict(zip(os_map.values(), os_map.keys()))
    arch_map_reverse = dict(zip(arch_map.values(), arch_map.keys()))

    os_name = os_map_reverse[ql.os.type]
    arch_name = arch_map_reverse[ql.arch.type]

    report = report.generate_report(ql)
    if hook_dictionary:
        report["hook"] = hook_dictionary

    while True:
        command = ask_report()

        if command == 'report':
            pprint(report)
        elif command == 'interactive report':
            Controller().run(DataSourceType.VARIABLE, report)
        elif command == 'report to pdf':
            time = datetime.now().strftime("%d_%m_%Y_%H_%M_%S")
            report_name = f"report_{ql.targetname.replace('.', '_')}_{os_name}_{arch_name}_{time}.pdf"
            pdfc = PdfConverter()
            with open(report_name, "wb") as pdf_fl:
               pdf_fl.write(pdfc.to_pdf(pdfc.to_html(json.dumps(report))))
               print(f"The report was saved in your current directory as {report_name}")
        elif command == 'quit':
            break


def want_to_hook():
    """
    Ask if user wants to hook
    """
    answer = questionary.confirm("Want to Hook:",
        default=False, auto_enter=True).ask()

    return answer


def ask_hook_type():
    """
    Ask for the type of hook
    """
    answer = questionary.select(
     "Select an Option:",
     choices=['hook_address', 'hook_code', 'hook_block', 'hook_intno',
              'hook_mem_unmapped', 'hook_mem_read_invalid',
              'hook_mem_write_invalid', 'hook_mem_fetch_invalid', 'hook_mem_invalid',
              'hook_mem_read', 'hook_mem_write', 'hook_mem_fetch']).ask()

    return answer.lower()


def ask_hook_operation():
    """
    Ask for the hook operation
    """
    answer = questionary.select(
     "Select an Option:",
     choices=['read', 'write', 'emu_start', 'emu_stop', 'save']).ask()

    return answer.lower()


def get_bytes_size():
    """
    Ask for bytes size
    """
    answer = questionary.text("bytes_size:", validate=IntValidator).ask()

    if re.match(HEX_REGEX, str(answer)):
        return int(answer, 16)

    return int(answer)


def ask_value():
    """
    Ask for value
    """
    answer = questionary.text("value:").ask()

    return bytes(answer, 'utf-8')


def ask_where():
    """
    Ask what to Hook
    """
    answer = questionary.select(
     "Select an Option:",
     choices=['Memory', 'Register']).ask()

    return answer.lower()[:3]


def ask_start_end():
    """
    Ask for start and end points for emulator start
    """
    start = questionary.text("address_start:").ask()
    end = questionary.text("address_end:", default="0x0").ask()

    return {"start": int(start, 16), "end": int(end, 16)}


def ask_address():
    """
    Ask for address to hook
    """
    address = questionary.text("address:", validate=HexValidator).ask()

    return int(address, 16)


def ask_hook_address():
    """
    Ask for address to hook
    """
    address = questionary.text("Hook Traget Address:", validate=HexValidator).ask()

    return int(address, 16)


def ask_register_name():
    """
    Ask register name
    """
    answer = questionary.text("register_name:").ask()

    return answer


def hook(ql):
    """
    Hook Function
    """

    log("Hook", HEADING_COLOR)

    hook_dictionary = {}

    do_hook = want_to_hook()

    if do_hook:
        hook_type = ask_hook_type()
        hook_dictionary["hook_type"] = hook_type

        operation = ask_hook_operation()
        hook_dictionary["operation"] = operation

        args = []
        user_data = {}

        if hook_type == "hook_address":
            hook_target_address = ask_hook_address()
            args.append(hook_target_address)
            hook_dictionary["hook_target_address"] = hook_target_address

        if operation in ['read', 'write']:
            where = ask_where()
            hook_dictionary["storage"] = where
            if where == 'mem':
                address = ask_address()
                user_data["address"] = address
                hook_dictionary["address"] = address
                if operation == 'read':
                    bytes_size = get_bytes_size()
                    user_data["bytes_size"] = bytes_size
                    hook_dictionary["bytes_size"] = bytes_size
                    operation = 'read_mem'
                else:
                    value = ask_value()
                    user_data["value"] = value
                    hook_dictionary["value"] = value
                    operation = 'write_mem'
            else:
                register_name = ask_register_name()
                user_data["register_name"] = register_name
                hook_dictionary["register_name"] = register_name
                if operation == 'read':
                    operation = 'read_reg'
                else:
                    value = ask_value()
                    user_data["value"] = value
                    hook_dictionary["value"] = value
                    operation = 'write_reg'

        if operation == 'emu_start':
            start_end = ask_start_end()
            user_data["start"] = start_end["start"]
            user_data["end"] = start_end["end"]
            hook_dictionary["start"] = start
            hook_dictionary["end"] = end

        if user_data:
            args.append(user_data)
            hook_dictionary["user_data"] = user_data

        if hook_type in ['hook_code', 'hook_block']:
            operation += '_4'

        elif hook_type in ['hook_mem_read', 'hook_mem_write']:
            operation += '_6'

        else:
            operation += '_2'

        getattr(ql, hook_type)(getattr(Callback_Functions, operation), *args)

    return hook_dictionary
