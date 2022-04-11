import sys
import os.path
from pathlib import Path
from types import ModuleType
from ida_kernwin import msg, warning
from importlib.machinery import ModuleSpec
from importlib.util import spec_from_file_location, module_from_spec


DIRECTORY: str = "C:\\Users\\titan\\Desktop\\BinAuthor"

module_path: Path = Path(DIRECTORY)
plugin_path: Path = module_path / "BinAuthor.py"

if not os.path.isdir(module_path):
    warning(f"Invalid path for BinAuthor module:\n{module_path}\n")
else:
    msg(f"Load BinAuthor module from path: {module_path}\n")
    # append module directory to system paths
    sys.path.append(DIRECTORY)
    if not os.path.isfile(plugin_path):
        warning(f"BinAuthor.py plugin not found at:\n{plugin_path}\n")
    else:
        msg(f"Load BinAuthor plugin: {plugin_path}\n")
        # create specification from plugin path
        spec: ModuleSpec = spec_from_file_location(__name__, plugin_path)
        # create module from specification
        plugin: ModuleType = module_from_spec(spec)
        # load the module
        spec.loader.exec_module(plugin)
        # export the plugin entry
        PLUGIN_ENTRY = plugin.PLUGIN_ENTRY
        msg(f"Successfully exported BinAuthor plugin entry!\n")
