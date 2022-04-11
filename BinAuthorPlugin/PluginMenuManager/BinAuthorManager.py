from sark.qt import MenuManager

from ida_kernwin import detach_action_from_menu, attach_action_to_menu, action_desc_t, SETMENU_APP, register_action

from BinAuthorPlugin.Views import BinaryIndexingView as BinaryIndexing
from BinAuthorPlugin.Views import ResultsView as Results
from BinAuthorPlugin.Views import MetricsView as Metrics
from BinAuthorPlugin.Algorithms.Choices import Choice1
from BinAuthorPlugin.Algorithms.Choices import Choice2
from BinAuthorPlugin.Algorithms.Choices import Choice18
from BinAuthorPlugin.Algorithms import AuthorClassification
from BinAuthorPlugin.Algorithms.Choices import Strings as StringsMatching


class BinAuthorManager():
    def __init__(self):
        self._menu = MenuManager()
        self.addmenu_item_ctxs = []
    
    def launchBinaryIndexing(self):
        self.indexing = BinaryIndexing.BinaryIndexing()
        self.indexing.create()
        self.indexing.show()
    
    def showMetrics(self):
        self.metricsResults = Metrics.Metrics()
        self.metricsResults.Show()
    
    def showResults(self):
        self.results = Results.Results()
        self.results.Show()
        
    def message(self,s):
        print(s)
    
    def del_menu_items(self):
        for addmenu_item_ctx in self.addmenu_item_ctxs:
            detach_action_from_menu(addmenu_item_ctx)

        self._menu.clear()
        
    def buildMenu(self,functionFilter):
        self._menu = MenuManager()
        self._menu.add_menu("&BinAuthor")
        choice1 = Choice1.Choice1()
        choice2 = Choice2.Choice2()
        choice18 = Choice18.Choice18()
        authorClassification = AuthorClassification.AuthorClassification()
        strings = StringsMatching._Strings()
        ui_path = "BinAuthor/"

        for action_name, action_label, callback in [
            ("author_indexing", "Author Indexing", self.launchBinaryIndexing),
            ("author_identification", "Author Identification", self.showMetrics),
            ("function_classification", "Function Classification", functionFilter.run),
            ("variable_utilization_features", "Variable Utilization Features", choice18.choice18),
            ("generalization_features", "Generalization Features", choice2.choice2),
            ("code_organization_features", "Code Organization Features", choice1.choice1),
            ("quality_features", "Quality Features", strings._Strings),
        ]:
            action_desc = action_desc_t(action_name, action_label, callback)
            if register_action(action_desc):
                attach_action_to_menu(ui_path, action_name, SETMENU_APP)
            else:
                print("Failed registering action '%s'" % action_name)
