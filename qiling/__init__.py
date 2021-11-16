from .core import Qiling
from .__version__ import __version__

def __git_info():
    """Retrieve git information of the current Qiling code base.
    """

    import os

    gitdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), r'..', r'.git')
    head_path = 'HEAD'

    try:
        with open(os.path.join(gitdir, head_path), 'r') as head_file:
            head_info = head_file.readline().rstrip()

        branch_path = os.path.join(gitdir, head_info.split('ref:', 1)[-1].lstrip())

        with open(os.path.join(gitdir, branch_path), 'r') as branch_file:
            commit = branch_file.readline().rstrip()

        branch = os.path.basename(branch_path)
    except OSError:
        branch = None
        commit = None

    return {
        'branch' : branch or 'unknown',
        'commit' : commit or 'unknown'
    }

def __platform_info():
    """Retrieve hosting platform information.
    """

    import platform

    return {
        'system'  : platform.system(),
        'release' : platform.release(),
        'machine' : platform.machine(),
        'python'  : platform.python_version()
    }

def __libs_info(modules):
    """Retrieve Python dependencies information.
    """

    def __module_ver(mname: str):
        """Query a module's version by name.
        """

        import importlib

        try:
            m = importlib.import_module(mname)
        except ModuleNotFoundError:
            v = None
        else:
            v = getattr(m, '__version__')

        return v

    return dict((mname, __module_ver(mname) or 'unknown') for mname in modules)

def ql_extended_info():
    """Collect extended information to help troubleshoot Qiling issues.
    """

    return {
        'git'      : __git_info(),
        'platform' : __platform_info(),
        'libs'     : __libs_info((
            'unicorn',
            'capstone',
            'keystone'
        ))
    }
