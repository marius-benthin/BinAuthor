from sark.qt import MenuManager

from ida_kernwin import (
    SETMENU_APP,
    detach_action_from_menu,
    attach_action_to_menu,
    action_desc_t,
    unregister_action,
    register_action,
    warning,
)

from BinAuthorPlugin.Views.MetricsView import MetricsHandler
from BinAuthorPlugin.Algorithms.Choices.Choice1 import Choice1Handler
from BinAuthorPlugin.Algorithms.Choices.Choice2 import Choice2Handler
from BinAuthorPlugin.Algorithms.Choices.Choice18 import Choice18Handler
from BinAuthorPlugin.Views.BinaryIndexingView import BinaryIndexingHandler
from BinAuthorPlugin.Views.FunctionFilterView import FunctionFilterHandler
from BinAuthorPlugin.Algorithms.Choices.Strings import CustomStringsHandler


class BinAuthorManager:

    """
    Maintains the BinAuthor top-level menu on the IDA Pro GUI
    """

    def __init__(self):
        self._menu = MenuManager()
        self._menu_items = []
        self._ui_name = "BinAuthor"
        self._ui_path = self._ui_name + "/"

    def del_menu_items(self):
        """
        Remove top-level menu and all sub-menu actions from IDA Pro GUI
        """
        for _item in self._menu_items:
            detach_action_from_menu(self._ui_path, _item)
            unregister_action(_item)
        self._menu.remove_menu(self._ui_name)
        self._menu.clear()
        
    def buildMenu(self, functionFilter):
        """
        Add top-level menu and sub-menu actions to IDA Pro GUI
        :param functionFilter: initialized BinAuthorFunctionFilter object
        """
        self._menu.add_menu(self._ui_name)
        for action_name, action_label, callback in [
            ("bin_author:author_indexing", "Author Indexing", BinaryIndexingHandler()),
            ("bin_author:author_identification", "Author Identification", MetricsHandler()),
            ("bin_author:function_classification", "Function Classification", FunctionFilterHandler(functionFilter)),
            ("bin_author:variable_utilization_features", "Variable Utilization Features", Choice18Handler()),
            ("bin_author:generalization_features", "Generalization Features", Choice2Handler()),
            ("bin_author:code_organization_features", "Code Organization Features", Choice1Handler()),
            ("bin_author:quality_features", "Quality Features", CustomStringsHandler()),
        ]:
            action_desc = action_desc_t(action_name, action_label, callback)
            if register_action(action_desc):
                attach_action_to_menu(self._ui_path, action_name, SETMENU_APP)
                self._menu_items.append(action_name)
            else:
                warning(f"Failed to register action: {action_name}")
