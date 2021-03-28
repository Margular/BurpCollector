#!coding:utf-8

"""
======
TEag1e@www.teagle.top
米斯特安全团队@www.hi-ourlife.com
======
"""

import collections
import json
import math
import os
import time

from burp import IBurpExtender
from burp import IContextMenuFactory
from burp import IExtensionStateListener
from javax.swing import JMenuItem

from MysqlController import MysqlController


class BurpExtender(IBurpExtender, IExtensionStateListener, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):

        # Set extension's name
        callbacks.setExtensionName('Burp Collector')

        self._callbacks = callbacks

        # create Log File
        self.createLogFile()

        # test the database connection
        MysqlController().connectTest()

        # retrieve the context menu factories
        callbacks.registerContextMenuFactory(self)

        # register ourselves as an Extension listener
        callbacks.registerExtensionStateListener(self)

    #
    # create log files with current time
    #

    def createLogFile(self):

        # currentTime = Year Month Day Hour Minute
        currentTime = time.strftime('%Y%m%d%H%M%S', time.localtime())

        # make directory
        if not os.path.exists('log'):
            os.mkdir('log')

        os.chdir('log')

        # make log file
        self._paramLog = '{}param.log'.format(currentTime)
        self._fileLog = '{}file.log'.format(currentTime)
        self._pathLog = '{}path.log'.format(currentTime)

        if not os.path.exists(self._paramLog):
            open(self._paramLog, 'w').close()
        if not os.path.exists(self._fileLog):
            open(self._fileLog, 'w').close()
        if not os.path.exists(self._pathLog):
            open(self._pathLog, 'w').close()

    #
    # implement IContextMenuFactory
    #

    def createMenuItems(self, invocation):

        mainMenu = JMenuItem('History To Log',
                             actionPerformed=self.menuOnClick)
        return [mainMenu]

    #
    # stores Data when Clicking on Context Menu
    #

    def menuOnClick(self, event):

        # extract path,file and param from Proxy History 
        DataExtractor(self._callbacks, self._pathLog, self._fileLog, self._paramLog)

    #
    # implement IExtensionStateListener
    #

    def extensionUnloaded(self):

        # extract path,file and param from Proxy History 
        DataExtractor(self._callbacks, self._pathLog, self._fileLog, self._paramLog)

        # stored in MySQL from the log file
        MysqlController().coreProcessor(self._pathLog, self._fileLog, self._paramLog)


#
# extract path,file and param from Proxy History 
#

class DataExtractor():

    def __init__(self, callbacks, pathLog, fileLog, paramLog):

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._pathLog = pathLog
        self._fileLog = fileLog
        self._paramLog = paramLog
        # self._entropyScore = 4.0
        with open('../config.ini')as config_f:
            self._config = json.load(config_f)
        # self._path_max_length = int(self._config.get('options').get('pathMaxLength'))
        # self._param_max_length = int(self._config.get('options').get('paramMaxLength'))
        # self._file_max_length = int(self._config.get('options').get('fileMaxLength'))
        self._entropyScore = self._config.get('options').get('entropy')
        self.coreProcessor()

    def entropy(self, word):
        if word.isdigit() and len(word) > 11:
            return 9
        inp_str = word
        counter_char = collections.Counter(inp_str)
        entropy = 0
        for c, ctn in counter_char.items():
            _p = float(ctn) / len(inp_str)
            entropy += -1 * _p * math.log(_p, 2)
        return round(entropy, 7)

    def coreProcessor(self):

        allHistoryMessage = self._callbacks.getProxyHistory()

        # define three variable to remove duplicate data
        collectionParam = []
        collectionFile = []
        collectionPath = []

        # processing each message
        for historyMessage in allHistoryMessage:

            httpService = historyMessage.getHttpService()

            # invoke host filter
            host = httpService.getHost()
            if not self.filterHost(host):
                continue

            requestInfo = self._helpers.analyzeRequest(httpService, historyMessage.getRequest())
            path = requestInfo.getUrl().getPath()
            path, file = self.formatPathFile(path)

            # file to log
            # invoke file filter
            if self.filterFile(file):
                try:
                    currentFile = '{}\t{}'.format(host, file)
                except:
                    pass
                else:
                    if file and currentFile not in collectionFile:
                        # print(currentFile)
                        with open(self._fileLog, 'a')as file_f:
                            file_f.write(currentFile + '\n')
                        collectionFile.append(currentFile)

            # parameters to log
            paramsObject = requestInfo.getParameters()
            params = self.processParamsObject(paramsObject)
            # UnicodeEncodeError

            # invoke param filter
            params = self.filterParam(params)
            try:
                currentParams = '{}\t{}'.format(host, ','.join(params))
            except:
                pass
            else:
                if params and currentParams not in collectionParam:
                    with open(self._paramLog, 'a')as params_f:
                        params_f.write(currentParams + '\n')
                    collectionParam.append(currentParams)

            # path to log
            # invoke path filter
            path = self.filterPath(path)
            try:
                currentPath = '{}\t{}'.format(host, path)
            except:
                pass
            else:
                if path and currentPath not in collectionPath:
                    # print(currentPath)
                    with open(self._pathLog, 'a')as path_f:
                        path_f.write(currentPath + '\n')
                    collectionPath.append(currentPath)

    # format path and file
    def formatPathFile(self, path):

        sepIndex = path.rfind('/')
        # EX: http://xxx/?id=1
        if path == '/':
            file = ''
            path = ''
        # EX: http://xxx/index.php
        # file = index.php
        elif sepIndex == 0:
            file = path[1:]
            path = ''
        # EX: http://xxx/x/index.php
        # path = /x/
        # file = index.php
        else:
            file = path[sepIndex + 1:]
            path = path[:sepIndex + 1]

        return path, file

    # extractor data from host
    def filterHost(self, host):

        blackHosts = self._config.get('blackHosts')

        for blackHost in blackHosts:
            if host.endswith(blackHost):
                return

        return True

    # extractor data from file
    def filterFile(self, file):
        v = self.entropy(file)

        balckPaths = self._config.get('blackExtension')

        for blackPath in balckPaths:
            if file.lower().endswith(blackPath):
                return False
        if v > self._entropyScore:
            print("file: {} entropy is {}, ignore".format(file, v))
            return False
        return True

    def filterPath(self, path):
        wordlist = path.split("/")[1:-1]
        c = 0
        for w in wordlist:
            v = self.entropy(w)
            if v > self._entropyScore:
                if c == 0:
                    return
                else:
                    newpath = '/' + '/'.join(wordlist[0:c]) + '/'
                print("path: {} entropy is {}, extract {}".format(path, v, newpath))
                return newpath
            c = c + 1
        return path

    def filterParam(self, params):
        newparams = []
        for p in params:
            e = self.entropy(p)
            if p == '':
                continue
            if e > self._entropyScore:
                # print(params)
                try:
                    print("param: %s entropy is %f, ignore" % (p, e))
                except:
                    # print(p,e)
                    pass
                continue
            newparams.append(p)
        return newparams

    # extract params
    def processParamsObject(self, paramsObject):

        # get parameters
        params = set()
        for paramObject in paramsObject:

            # don't process Cookie's Pamrams
            if paramObject.getType() == 2:
                continue
            param = paramObject.getName()
            if param.startswith('_'):
                continue
            params.add(param)
        return params
