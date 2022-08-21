import os
import ast
import pickle
import re
import six
import argparse
from pyfx import Controller
from pyfx.model import DataSourceType

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


def env_arg(value):
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
    return verbose_map[value]


# read code from file
def read_file(fname: str):
    with open(fname, "rb") as f:
        content = f.read()

    return content


def log(string, color):
    if colored:
        six.print_(colored(string, color))
    else:
        six.print_(string)


class IntValidator(Validator):
    def validate(self, value):
        try:
            int(value.text)
            return True
        except:
            raise ValidationError(
                message="Integer required",
                cursor_position=len(value.text))


class DirectoryPathValidator(Validator):
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
    answer = questionary.select(
     "Select an Option:",
     choices=['Run', 'Code']).ask()

    return answer.lower()


def ask_run_options():
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
    answer = questionary.confirm("Show Report:",
        default=True, auto_enter=True).ask()

    return answer


def show_report(report):
    log("Report", HEADING_COLOR)

    while True:
        show = ask_report()

        if show:
            Controller().run(DataSourceType.VARIABLE, report)
        else:
            break
