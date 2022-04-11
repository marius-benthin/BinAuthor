from pymongo import MongoClient
from os.path import dirname, realpath
from PyQt5 import QtGui, QtCore, QtWidgets, uic

from idaapi import PluginForm

from BinAuthorPlugin.Algorithms import AuthorClassification


class Metrics(PluginForm):
    def returnColor(self,percentage):
        percentage = (1-percentage) * 100
        #R = (255 * percentage) / 100
        #G = (255 * (100 - percentage)) / 100
        #B = 0
        
        if percentage < 50:
            R = 255 * (percentage/50)
            G = 255
        else:
            R = 255
            G = 255 * ((50 - percentage % 50) / 50)
        B = 0
        return QtGui.QColor(R,G,B)
    def getChoice1Classification(self):
        self.choice1Stats = self.authorClassification.getChoice1()
        return self.choice1Stats
        
    def getChoice2Classification(self):
        self.choice2Stats = self.authorClassification.getChoice2()
        return self.choice2Stats
    
    def getChoice18Classification(self):
        self.choice18Stats = self.authorClassification.getChoice18()
        return self.choice18Stats
        
    def getStringSimilaritiesClassification(self):
        self.StringStats = self.authorClassification.getStringSimilarityScores()
        return self.StringStats
    
    def getAuthorsList(self):
        self.client = MongoClient('localhost', 27017)
        self.db = self.client.BinAuthor
        self.choice1 = self.db.Choice1
        
        authorsList = self.choice1.distinct("Author Name")
        self.authors = {}
        self.authorRanking = {}
        
        
        
        for result in authorsList:
            
            if result in self.StringStats.keys():
                stringsstat = self.StringStats[result]["score"]
            else:
                stringsstat = 0
            
            if result in self.choice1Stats.keys():
                choice1stat = self.choice1Stats[result]
            else:
                choice1stat = 0
            
            if result in self.choice2Stats.keys():
                choice2stat = self.choice2Stats[result]
            else:
                choice2stat = 0
                
            if result in self.choice18Stats.keys():
                choice18stat = self.choice18Stats[result]
            else:
                choice18stat = 0
            
            self.authors[result] = {"choice1": choice1stat,"choice2": choice2stat,"choice18": choice18stat,"strings": stringsstat}
            self.authorRanking[result] = (0.2*choice1stat + 0.15*choice2stat + 0.05*choice18stat + 0.6*stringsstat)
            
        #authorSum = 0
        #for author in self.authorRanking.keys():
        #    authorSum += self.authorRanking[author]
            
        #for author in self.authorRanking.keys():
        #    self.authorRanking[author] = self.authorRanking[author]/authorSum

        
    def OnCreate(self,form):
        self.parent = self.FormToPySideWidget(form)
        self.wid = QtWidgets.QWidget()
        binaryUIPath = os.path.dirname(os.path.realpath(__file__)) + "\\UI\\MetricsView.ui"
        file = QtCore.QFile(binaryUIPath)
        file.open(QtCore.QFile.ReadOnly)
        myWidget = uic.loadUi(file, self.wid)
        self.authorClassification = AuthorClassification.AuthorClassification()
        self.getChoice1Classification()
        self.getChoice2Classification()
        self.getChoice18Classification()
        self.getStringSimilaritiesClassification()
        # Grid
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(myWidget)

        self.getAuthorsList()
        
        comboBoxes = self.wid.findChildren(QtWidgets.QComboBox)
        tableView = self.wid.findChildren(QtWidgets.QTableWidget,"tableWidget")[0]
        authorTableView = self.wid.findChildren(QtWidgets.QTableWidget,"tableWidget_2")[0]
        for combo in comboBoxes:
            if "comboBox" in combo.objectName():
                combo.insertItems(0,["1","5","10","15","50","100"])
                
                    
        for author in self.authors.keys():
            count = tableView.rowCount()
            tableView.insertRow(count)
            authorName = QtWidgets.QTableWidgetItem(author)
            tableView.setItem(count,0,authorName)
            
            if 'strings' in self.authors[author].keys():
                stringSimilarity = QtWidgets.QTableWidgetItem(str(self.authors[author]["strings"]))
                tableView.setItem(count,1,stringSimilarity)
            
            if 'choice1' in self.authors[author].keys():
                choice1Similarity = QtWidgets.QTableWidgetItem(str(self.authors[author]["choice1"]))
                tableView.setItem(count,2,choice1Similarity)
                
            if 'choice2' in self.authors[author].keys():
                choice2Similarity = QtWidgets.QTableWidgetItem(str(self.authors[author]["choice2"]))
                tableView.setItem(count,3,choice2Similarity)
                
            if 'choice18' in self.authors[author].keys():
                choice18Similarity = QtWidgets.QTableWidgetItem(str(self.authors[author]["choice18"]))
                tableView.setItem(count,4,choice18Similarity)
        
        sortedAuthorMatches = sorted(self.authorRanking,key=self.authorRanking.get,reverse=True)
        
        
        for author in sortedAuthorMatches:
            count = authorTableView.rowCount()
            authorTableView.insertRow(count)
            authorName = QtWidgets.QTableWidgetItem(author)
            authorTableView.setItem(count,0,authorName)
            authorSimilarity = QtWidgets.QTableWidgetItem(str(self.authorRanking[author]*100))
            authorTableView.setItem(count,1,authorSimilarity)
            authorTableView.item(count,1).setBackground(self.returnColor(self.authorRanking[author]))
            authorTableView.item(count,0).setBackground(self.returnColor(self.authorRanking[author]))
            
        file.close()
        self.parent.setLayout(layout)

    def Show(self):
        """Creates the form is not created or focuses it if it was"""
        return PluginForm.Show(self,"Author Identification", options = PluginForm.FORM_PERSIST)
