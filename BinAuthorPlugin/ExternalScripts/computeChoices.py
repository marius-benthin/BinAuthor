from idc import ARGV
from ida_auto import auto_wait
from ida_pro import qexit

from BinAuthorPlugin.Algorithms.Choices.Choice1 import Choice1
from BinAuthorPlugin.Algorithms.Choices.Choice2 import Choice2
from BinAuthorPlugin.Algorithms.Choices.Choice18 import Choice18
from BinAuthorPlugin.Algorithms.Choices.Strings import CustomStrings

# wait for auto-analysis to finish
auto_wait()

# get author name from command line parameter
authorName = ARGV[1]

# extract features
strings = CustomStrings(authorName)
strings.CustomStrings()
choice1 = Choice1(authorName)
choice1.choice1()
choice2 = Choice2(authorName)
choice2.choice2()
choice18 = Choice18(authorName)
choice18.choice18()

# exit IDA Pro
qexit(0)
