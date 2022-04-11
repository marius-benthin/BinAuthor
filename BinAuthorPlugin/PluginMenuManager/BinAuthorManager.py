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
        self._menu = sark.qt.MenuManager()
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
            idaapi.del_menu_item(addmenu_item_ctx)

        self._menu.clear()
        
    def buildMenu(self,functionFilter):
        self._menu = sark.qt.MenuManager()
        self._menu.add_menu("&BinAuthor")
        choice1 = Choice1.Choice1()
        choice2 = Choice2.Choice2()
        choice18 = Choice18.Choice18()
        authorClassification = AuthorClassification.AuthorClassification()
        strings = StringsMatching._Strings()
        self.addmenu_item_ctxs.append(idaapi.add_menu_item("BinAuthor/", "Author Indexing", "", 0, self.launchBinaryIndexing, ()))
        self.addmenu_item_ctxs.append(idaapi.add_menu_item("BinAuthor/", "Author Identification", "", 0, self.showMetrics, ()))
        self.addmenu_item_ctxs.append(idaapi.add_menu_item("BinAuthor/", "Function Classification", "", 0, functionFilter.run, ()))
        self.addmenu_item_ctxs.append(idaapi.add_menu_item("BinAuthor/", "Variable Utilization Features", "", 0, choice18.choice18, ()))
        self.addmenu_item_ctxs.append(idaapi.add_menu_item("BinAuthor/", "Generalization Features", "", 0, choice2.choice2, ()))
        self.addmenu_item_ctxs.append(idaapi.add_menu_item("BinAuthor/", "Code Organization Features", "", 0, choice1.choice1, ()))
        self.addmenu_item_ctxs.append(idaapi.add_menu_item("BinAuthor/","Quality Features", "", 0, strings._Strings, ()))
