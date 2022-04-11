def PLUGIN_ENTRY():

    from ida_kernwin import msg, warning
    from ida_idaapi import plugin_t, PLUGIN_PROC, PLUGIN_SKIP, PLUGIN_KEEP

    from BinAuthorPlugin.PluginMenuManager import BinAuthorManager as BinAuthorManager
    from BinAuthorPlugin.Algorithms import FunctionFliterAndColorizer as FunctionFilter

    class BinAuthor_plugin_t(plugin_t):
        flags = PLUGIN_PROC
        comment = "Author Identification using Novel Techniques"
        help = "Help if a matter of trust."
        wanted_name = "BinAuthor"
        wanted_hotkey = ""

        def __init__(self):
            self.BinAuthor_manager = None
            self.BinAuthorFunctionFilter = None
            self.BinAuthorFeatureExtractor = None

        def init(self):
            try:
                self.BinAuthorFunctionFilter = FunctionFilter.FunctionFilter()
            except Exception as e:
                msg(e)
                warning("Failed to initialize Function Filter.\n")
                warning("Failed to initialize BinAuthor.\n")
                del self.BinAuthorFeatureExtractor
                warning("Errors and fun!\n")
                return PLUGIN_SKIP

            try:
                self.BinAuthor_manager = BinAuthorManager.BinAuthorManager()
                self.BinAuthor_manager.buildMenu(self.BinAuthorFunctionFilter)
                return PLUGIN_KEEP
            except Exception as e:
                msg(e)
                warning("Failed to initialize BinAuthor.\n")
                del self.BinAuthor_manager
                warning("Errors and fun!\n")
                return PLUGIN_SKIP

        def term(self):
            self.BinAuthor_manager.del_menu_items()

        def run(self, arg):
            pass

    return BinAuthor_plugin_t()
