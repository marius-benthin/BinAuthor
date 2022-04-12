from matplotlib import use, pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from PyQt5 import QtWidgets

from ida_kernwin import PluginForm, action_handler_t, AST_ENABLE_ALWAYS

from BinAuthorPlugin.Views import StatisticsView as StatsView

use('Qt5Agg')


class FunctionFilterHandler(action_handler_t):

    """
    Action handler that holds previously initializes FunctionFilter for IDA Pro GUI
    """

    def __init__(self, functionFilter):
        action_handler_t.__init__(self)
        self.function_filter = functionFilter

    def activate(self, ctx):
        self.function_filter.run()
        return 1

    def update(self, ctx):
        return AST_ENABLE_ALWAYS


class FunctionFilterList(PluginForm):

    def __init__(self):
        super().__init__()
        self.results_tree = None
        self.parent = None
        self.statisticsView = None
        self.funcTypeDict = None
        self.pieStats = None
        self.items = []

    def imports_names_cb(self, ea, name, _ord):
        self.items.append((ea, '' if not name else name, _ord))
        # True -> Continue enumeration
        return True

    def setDetails(self, pieStats, funcTypeDict):
        self.pieStats = pieStats
        self.funcTypeDict = funcTypeDict

    def OnCreate(self, form):
        """
        Called when the plugin form is created
        """
        self.statisticsView = None
        # Get parent widget
        self.parent = self.FormToPySideWidget(form)

        w = QtWidgets.QWidget()
        # w.resize(200, 200)
        # w.move(100, 300)
        # w.setWindowTitle('Simple')

        # The slices will be ordered and plotted counter-clockwise.
        labels = 'User', 'Compiler', 'Other'
        sizes = self.pieStats  # [15, 55, 30]
        colors = ['#80FFCC', '#ACC7FF', '#CC6600']
        explode = (0, 0.1, 0)  # only "explode" the 2nd slice (i.e. 'Hogs')

        plt.pie(sizes, explode=explode, labels=labels, colors=colors,
                autopct='%1.1f%%', shadow=True, startangle=90)
        # Set aspect ratio to be equal so that pie is drawn as a circle.
        plt.axis('equal')
        figure = plt.figure(figsize=(10, 0.2))
        figure.set_facecolor(None)
        figure.patch.set_alpha(0.0)
        canvas = FigureCanvas(figure)
        axes = figure.add_subplot(111)
        axes.pie(sizes, explode=explode, labels=labels, colors=colors,
                 autopct='%1.1f%%', shadow=True, startangle=90)

        self.results_tree = QtWidgets.QTreeWidget()
        self.results_tree.setSortingEnabled(False)
        self.results_tree.headerItem().setText(0, 'Function Type')
        self.results_tree.headerItem().setText(1, 'Function Name')

        """
        exampleFunctionTypes = {"User":["__ArrayUnwind(void *,uint,int,void (*)(void *))",
        "std::char_traits<char>::compare(char const *,char const *,uint)","solve(int)","_main",
        "std::_Tree_val<std::_Tset_traits<std::basic_string<char,std::char_traits<char>,std::allocator<char>>,
        std::less<std::basic_string<char,std::char_traits<char>,std::allocator<char>>>,
        std::allocator<std::basic_string<char,std::char_traits<char>,std::allocator<char>>>,
        0>>::~_Tree_val<std::_Tset_traits<std::basic_string<char,std::char_traits<char>,std::allocator<char>>,
        std::less<std::basic_string<char,std::char_traits<char>,std::allocator<char>>>,
        std::allocator<std::basic_string<char,std::char_traits<char>,std::allocator<char>>>,0>>(void)",
        "std::basic_string<char,std::char_traits<char>,std::allocator<char>>::insert(uint,uint,char)",
        "?erase@?$_Tree@V?$_Tset_traits@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@U?$less@V
        ?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@2@V?$allocator@V?$basic_string@DU?$char_traits
        @D@std@@V?$allocator@D@2@@std@@@2@$0A@@std@@@std@@QAE?AV?$_Tree_const_iterator@V?$_Tree_val@V?$_Tset_traits@V
        ?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@U?$less@V?$basic_string@DU?$char_traits@D@std@@V
        ?$allocator@D@2@@std@@@2@V?$allocator@V?$basic_string@DU?$char_traits@D@std@@V?$al_"],"Compiler":[
        "std::bad_alloc::`vector deleting destructor'(uint)","std::set<std::basic_string<char,std::char_traits<char>,
        std::allocator<char>>,std::less<std::basic_string<char,std::char_traits<char>,std::allocator<char>>>,
        std::allocator<std::basic_string<char,std::char_traits<char>,
        std::allocator<char>>>>::~set<std::basic_string<char,std::char_traits<char>,std::allocator<char>>,
        std::less<std::basic_string<char,std::char_traits<char>,std::allocator<char>>>,
        std::allocator<std::basic_string<char,std::char_traits<char>,std::allocator<char>>>>(void)",
        "std::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string<char,
        std::char_traits<char>,std::allocator<char>>(void)","std::basic_string<char,std::char_traits<char>,
        std::allocator<char>>::assign(char const *,uint)"],"Other":["??1bad_alloc@std@@UAE@XZ","operator delete(void 
        *,void *)","__security_check_cookie(x)","std::exception::what(void)","std::exception::exception(
        std::exception const &)","operator delete(void *)"]}
        """

        counter = 0
        for funcType in self.funcTypeDict.keys():
            funcTypeTree = QtWidgets.QTreeWidgetItem(self.results_tree)
            funcTypeTree.setText(0, funcType)
            funcTreeCounter = 0
            for funcName in self.funcTypeDict[funcType]:
                funcItem = QtWidgets.QTreeWidgetItem(funcTypeTree)
                funcItem.setText(0, funcType)
                funcItem.setText(1, funcName)
                funcTreeCounter += 1
            counter += 1
            self.results_tree.addTopLevelItem(funcTypeTree)
        canvas.resize(20, 20)
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(canvas)
        w.setLayout(layout)
        w.setFixedWidth(500)
        w.setFixedHeight(500)

        self.results_tree.itemClicked.connect(self.item_click)
        layoutMain = QtWidgets.QGridLayout()
        layoutMain.addWidget(w, 0, 0)
        layoutMain.addWidget(self.results_tree, 0, 1)
        canvas.draw()
        # Populate PluginForm
        self.parent.setLayout(layoutMain)

    def item_click(self, item):
        print(str(item.text(1)))
        self.statisticsView = StatsView.StatsView()
        self.statisticsView.setDetails(item.text(1))
        self.statisticsView.Show()

    def OnClose(self, form):
        """
        Called when the plugin form is closed
        """
        # global ImpExpForm
        # del ImpExpForm
        print("Closed")

    def Show(self, caption="Function Classes", options=PluginForm.WOPN_PERSIST):
        """Creates the form is not created or focuses it if it was"""
        return PluginForm.Show(self, caption=caption, options=options)
