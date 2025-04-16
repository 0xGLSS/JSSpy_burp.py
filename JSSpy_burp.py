"""
A Burp Suite extension for tracking JavaScript files and URLs in web applications.

This extension integrates with Burp Suite Community and Professional to help security researchers and web developers:
- Automatically detect and extract JavaScript file URLs from HTTP traffic
- Track JavaScript file changes and versions over time
- Send discovered JavaScript files to a centralized tracking service
- View results in a custom Burp Suite tab interface

Features:
- Context menu integration for sending JavaScript URLs to tracker
- API key configuration and connection testing
- Efficient regex-based JavaScript URL detection
- Clean UI with configuration panel and output area

Author: JSSpy Team
"""

# -*- coding: utf-8 -*-
from burp import IBurpExtender, IContextMenuFactory, ITab
from javax.swing import JMenuItem, JPanel, JTextField, JLabel, JTextArea, JScrollPane, BoxLayout, JButton, SwingWorker
from java.awt import BorderLayout, Dimension
from java.util import ArrayList
from java.net import URL
import json
import urllib2
import re
import os

class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        
        # Set extension name
        callbacks.setExtensionName("JSSpy JS Monitor")
        
        # Initialize UI
        self.initUI()
        
        # Register as context menu factory
        callbacks.registerContextMenuFactory(self)
        
        # Add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        
        # Define your API endpoint
        self.api_endpoint = "https://www.jsspy.xyz/api/burp/add"
        
        # Load saved API key
        self.loadApiKey()
        
        self.log("JSSpy JS Monitor loaded")
        self.log("API Endpoint: " + self.api_endpoint)

    def loadApiKey(self):
        try:
            config_file = os.path.join(os.path.expanduser("~"), ".jsspy_config.json")
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    if 'api_key' in config:
                        self.apiKeyField.setText(config['api_key'])
                        self.log("API key loaded from config")
        except Exception as e:
            self.log("Error loading API key: " + str(e))

    def saveApiKey(self):
        try:
            config_file = os.path.join(os.path.expanduser("~"), ".jsspy_config.json")
            config = {'api_key': self.apiKeyField.getText()}
            with open(config_file, 'w') as f:
                json.dump(config, f)
            self.log("API key saved to config")
        except Exception as e:
            self.log("Error saving API key: " + str(e))

    def initUI(self):
        # Create main panel
        self.panel = JPanel(BorderLayout())
        
        # Create config panel
        configPanel = JPanel()
        configPanel.setLayout(BoxLayout(configPanel, BoxLayout.X_AXIS))
        
        # Add API key input
        apiKeyLabel = JLabel("API Key: ")
        self.apiKeyField = JTextField("", 40)
        configPanel.add(apiKeyLabel)
        configPanel.add(self.apiKeyField)
        
        # Add test button
        testButton = JButton("Add Key", actionPerformed=self.testConnection)
        configPanel.add(testButton)
        
        # Add config panel to main panel
        self.panel.add(configPanel, BorderLayout.NORTH)
        
        # Create output text area
        self.outputArea = JTextArea()
        self.outputArea.setEditable(False)
        scrollPane = JScrollPane(self.outputArea)
        scrollPane.setPreferredSize(Dimension(800, 600))
        
        # Add output area to main panel
        self.panel.add(scrollPane, BorderLayout.CENTER)

    def testConnection(self, event):
        class TestConnectionWorker(SwingWorker):
            def __init__(self, parent):
                SwingWorker.__init__(self)
                self.parent = parent

            def doInBackground(self):
                api_key = self.parent.apiKeyField.getText()
                if not api_key:
                    self.parent.log("Error: No API key provided")
                    return
                
                try:
                    url = self.parent.api_endpoint + "?api_key=" + api_key
                    request = urllib2.Request(url)
                    request.add_header('Content-Type', 'application/json')
                    request.add_data(json.dumps({"urls": []}))
                    
                    response = urllib2.urlopen(request)
                    if response.getcode() == 200:
                        self.parent.log("API key is valid")
                        # Save the API key if it's valid
                        self.parent.saveApiKey()
                    else:
                        self.parent.log("API key is invalid")
                except Exception as e:
                    self.parent.log("Connection failed: " + str(e))
            
            def done(self):
                pass

        worker = TestConnectionWorker(self)
        worker.execute()

    def createMenuItems(self, invocation):
        self.context = invocation
        menuList = ArrayList()
        menuList.add(JMenuItem("Send to JSSpy", actionPerformed=lambda x: self.sendToTracker(invocation)))
        return menuList

    def sendToTracker(self, invocation):
        api_key = self.apiKeyField.getText()
        if not api_key:
            self.log("Error: No API key provided")
            return

        http_messages = invocation.getSelectedMessages()
        if http_messages is None or len(http_messages) == 0:
            self.log("Error: No messages selected")
            return

        js_pattern = re.compile(r'https?://[^\s<>"\']+?\.js', re.IGNORECASE)
        js_urls = set()

        try:
            for message in http_messages:
                request_info = self.helpers.analyzeRequest(message)
                url = str(request_info.getUrl())
                
                if url.lower().endswith('.js'):
                    js_urls.add(url)
                
                if message.getResponse():
                    response = message.getResponse()
                    response_info = self.helpers.analyzeResponse(response)
                    body_offset = response_info.getBodyOffset()
                    response_body = self.helpers.bytesToString(response[body_offset:])
                    found_urls = js_pattern.findall(response_body)
                    js_urls.update(found_urls)

        except Exception as e:
            self.log("Error processing messages: " + str(e))
            return

        if not js_urls:
            self.log("No JavaScript URLs found")
            return

        self.log("Processing %d URLs..." % len(js_urls))
        batch_size = 50
        js_urls_list = list(js_urls)
        batches = [js_urls_list[i:i + batch_size] for i in range(0, len(js_urls_list), batch_size)]
        
        class SendToTrackerWorker(SwingWorker):
            def __init__(self, parent, batches, api_key):
                SwingWorker.__init__(self)
                self.parent = parent
                self.batches = batches
                self.api_key = api_key

            def doInBackground(self):
                for index, batch in enumerate(self.batches):
                    try:
                        data = json.dumps({"urls": batch})
                        url = "%s?api_key=%s" % (self.parent.api_endpoint, self.api_key)
                        
                        request = urllib2.Request(url)
                        request.add_header('Content-Type', 'application/json')
                        request.add_data(data)
                        
                        response = urllib2.urlopen(request)
                        result = json.loads(response.read())
                        
                        for r in result.get('results', []):
                            status = r.get('status', 'unknown')
                            url_str = r.get('url', 'unknown')
                            message = r.get('message', '')
                            
                            msg = "[%s] %s%s" % (
                                '+' if status == 'success' else '-',
                                url_str,
                                " - %s" % message if message else ""
                            )
                            self.parent.log(msg)
                    except Exception as e:
                        self.parent.log("Error: " + str(e))
                        continue
            
            def done(self):
                self.parent.log("Processing complete")

        worker = SendToTrackerWorker(self, batches, api_key)
        worker.execute()

    def log(self, message):
        """Enhanced logging with timestamp"""
        from datetime import datetime
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.outputArea.append("[%s] %s\n" % (timestamp, message))
        self.outputArea.setCaretPosition(self.outputArea.getDocument().getLength())

    def getTabCaption(self):
        return "JSSpy"
        
    def getUiComponent(self):
        return self.panel

