# /usr/bin/env python
# _*_ coding:utf-8 _*_
from burp import IBurpExtender
from burp import ITab
from burp import IHttpListener
from burp import IMessageEditorController
from java.awt import Component;
from java.io import PrintWriter;
from java.util import ArrayList;
from java.util import List;
from javax.swing import JScrollPane;
from javax.swing import JSplitPane;
from javax.swing import JTabbedPane;
from javax.swing import JTable;
from javax.swing import SwingUtilities;
from javax.swing.table import AbstractTableModel;
from threading import Lock
import urllib
import re
import os
import sys
reload(sys)
sys.setdefaultencoding('utf8')

class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, AbstractTableModel):
    
    #
    # implement IBurpExtender
    #
    
    def	registerExtenderCallbacks(self, callbacks):
        print("[+]################################")
        print("[+]    JSONP + CORS 漏洞检测")
        print("[+]    Author: 挖低位的清风")
        print("[+]    versions: Bate 1.0")
        print("[+]################################")
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("Jsonp++")
        
        # create the log and a lock on which to synchronize when adding log entries
        self._log = ArrayList()
        self._lock = Lock()
        
        # main split pane
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        
        # table of log entries
        logTable = Table(self)
        scrollPane = JScrollPane(logTable)
        self._splitpane.setLeftComponent(scrollPane)

        # tabs with request/response viewers
        tabs = JTabbedPane()
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)
        tabs.addTab("Request", self._requestViewer.getComponent())
        tabs.addTab("Response", self._responseViewer.getComponent())
        self._splitpane.setRightComponent(tabs)
        
        # customize our UI components
        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(logTable)
        callbacks.customizeUiComponent(scrollPane)
        callbacks.customizeUiComponent(tabs)
        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        
        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)
        
        return
        
    #
    # implement ITab
    #
    
    def getTabCaption(self):
        return "Jsonp++"
    
    def getUiComponent(self):
        return self._splitpane
        
    #
    # implement IHttpListener
    #
    #def cors_jsonp(self, messageInfo):
        
    def processHttpMessage(self, toolFlag, messageIsRequest,messageInfo):
        # only process requests
        global url
        global request_method 
        if messageIsRequest:
            request = messageInfo.getRequest() # byte流的数据
            analyzedRequest = self._helpers.analyzeRequest(request) # 获取request数据
            request_header = list(analyzedRequest.getHeaders()) # 获取请求头,这里是个坑，必须要转为 list 不然 Python  append 的时候会报错
            request_method = analyzedRequest.getMethod() # 获取请求方式
            request_bodys = request[analyzedRequest.getBodyOffset():].tostring() # 获取请求包
            num = -1
            for i in request_header:
                num = num + 1
                if u'rigin:' in i:
                    request_header[num] = u'Origin: Origin.example.org' # 如果有 Origin 就替换
                if u'Referer:' in i:
                    request_header[num] = u'Referer: Referer.example.org' # 如果有 Referer 就删除
            if 'Origin:' not in ','.join(request_header):
                request_header.append(u'Origin: foo.example.org') # 如果没有 Origin 就添加
            newRequest = self._helpers.buildHttpMessage(request_header, request_bodys)
            test = messageInfo.setRequest(newRequest)#重新发送数据

        else:
            response = messageInfo.getResponse()
            url = self._helpers.analyzeRequest(messageInfo).getUrl() # 获取 URL
            analyzedResponse = self._helpers.analyzeResponse(response) # 获取response数据
            Response_header = analyzedResponse.getHeaders() # 获取返回头
            res_code = analyzedResponse.getStatusCode() # 获取状态码
            res_mime = analyzedResponse.getStatedMimeType() # 获取mime
            res_bodys = response[analyzedResponse.getBodyOffset():].tostring()
            Origin = "Origin.example.org"
            Origin1 = "foo.example.org"
            Referer = "Referer.example.org"
            vuln = ['CORS VULN','JSONP VULN']
            # 判断 CORS 漏洞
            if Origin in str(Response_header):
                self._log.add(LogEntry(toolFlag, self._callbacks.saveBuffersToTempFiles(messageInfo), url, res_code, res_mime, request_method,vuln[0]))
            #获取 key value
            iRrequestInfo = self._helpers.analyzeRequest(messageInfo)
            iParameters = iRrequestInfo.getParameters()
            key = []
            value = []
            mime = ["script","text","JSON",'HTML']
            for i in iParameters:
                #print ('key ' + i.getName())
                key.append(str(i.getName()))
                value.append(str(i.getValue()))
            #print (key)
            #print(res_bodys + '\n')

            # 判断 jsopn 跨域获取漏洞
            if res_mime in mime and ".js" not in str(url) and request_method == 'GET':
                # 获取 正则 匹配后的正文
                try:
                    res_bodys1 = (re.findall(".*\(({.*})\).*", res_bodys, re.S))[0]
                except:
                    pass
                else:
                    #print(res_bodys1)
                    # 删除 JSON 数据 后的字符串
                    b = res_bodys.replace(res_bodys1,'')
                    c = b.replace('()','')
                    for i in value:
                        ii = urllib.unquote(i)
                        if ii in c and len(c) - len(ii) < 6:
                            self._log.add(LogEntry(toolFlag, self._callbacks.saveBuffersToTempFiles(messageInfo), url, res_code, res_mime, request_method,vuln[1]))

        self._lock.acquire()
        row = self._log.size()
        self.fireTableRowsInserted(row, row)
        self._lock.release()



    #
    # extend AbstractTableModel
    #
    
    def getRowCount(self):
        try:
            return self._log.size()
        except:
            return 0

    def getColumnCount(self):
        return 6

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "Tool"
        if columnIndex == 1:
            return "Method"
        if columnIndex == 2:
            return "URL"
        if columnIndex == 3:
            return "MIME"
        if columnIndex == 4:
            return "Code"
        if columnIndex == 5:
            return "Vulnerability"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex) #调用logEntry
        if columnIndex == 0:
            return self._callbacks.getToolName(logEntry._tool)
        if columnIndex == 1:
            return logEntry._method
        if columnIndex == 2:
            return logEntry._url.toString()
        if columnIndex == 3:
            return logEntry._mime
        if columnIndex == 4:
            return logEntry._code
        if columnIndex == 5:
            return logEntry._vuln
    #
    # implement IMessageEditorController
    # this allows our request/response viewers to obtain details about the messages being displayed
    #
    
    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()

#
# extend JTable to handle cell selection
#
    
class Table(JTable):
    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)
    
    def changeSelection(self, row, col, toggle, extend):
    
        # show the log entry for the selected row
        logEntry = self._extender._log.get(row)
        self._extender._requestViewer.setMessage(logEntry._requestResponse.getRequest(), True)
        self._extender._responseViewer.setMessage(logEntry._requestResponse.getResponse(), False)
        self._extender._currentlyDisplayedItem = logEntry._requestResponse
        
        JTable.changeSelection(self, row, col, toggle, extend)
    
#
# class to hold details of each log entry
#

class LogEntry:
    def __init__(self ,tool, requestResponse, url, code, mime,method,vuln):
        self._tool = tool
        self._method = method
        self._requestResponse = requestResponse
        self._url = url
        self._code = code
        self._mime = mime
        self._vuln = vuln
