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
from javax.swing import JMenuItem, JPanel, JTextField, JLabel, JTextArea, JScrollPane, BoxLayout, JButton
from java.awt import BorderLayout, Dimension
from java.util import ArrayList
from java.net import URL
import json
import urllib2
import re

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
        self.api_endpoint = "http://jsspy.xyz/api/burp/add"
        
        print("JSSpy JS Monitor loaded!")
        print("API Endpoint:", self.api_endpoint)

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
        testButton = JButton("Test Connection", actionPerformed=self.testConnection)
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
        try:
            api_key = self.apiKeyField.getText()
            if not api_key:
                self.log("Please enter an API key")
                return
                
            url = self.api_endpoint + "?api_key=" + api_key
            request = urllib2.Request(url)
            request.add_header('Content-Type', 'application/json')
            request.add_data(json.dumps({"urls": []}))
            
            response = urllib2.urlopen(request)
            if response.getcode() == 200:
                self.log("Connection successful! API key is valid.")
            else:
                self.log("Connection failed! Status code: " + str(response.getcode()))
        except Exception as e:
            self.log("Connection failed! Error: " + str(e))

    def log(self, message):
        self.outputArea.append(message + "\n")
        self.outputArea.setCaretPosition(self.outputArea.getDocument().getLength())

    def getTabCaption(self):
        return "JSSpy"
        
    def getUiComponent(self):
        return self.panel

    def createMenuItems(self, invocation):
        self.context = invocation
        menuList = ArrayList()
        menuList.add(JMenuItem("Send to JSSpy", 
                             actionPerformed=lambda x: self.sendToTracker(invocation)))
        return menuList

    def sendToTracker(self, invocation):
        # Get API key from UI
        api_key = self.apiKeyField.getText()
        if not api_key:
            self.log("Please enter an API key in the JSSpy tab")
            return

        # Get selected messages
        http_messages = invocation.getSelectedMessages()
        if http_messages is None or len(http_messages) == 0:
            self.log("No messages selected")
            return

        # Pre-compile regex pattern
        js_pattern = re.compile(r'https?://[^\s<>"\']+?\.js', re.IGNORECASE)
        js_urls = set()  # Use set for automatic deduplication

        try:
            for message in http_messages:
                # Get request details
                request_info = self.helpers.analyzeRequest(message)
                url = str(request_info.getUrl())
                
                # Check if it's a JavaScript file
                if url.lower().endswith('.js'):
                    js_urls.add(url)
                
                # Check response for JavaScript URLs
                if message.getResponse():
                    response = message.getResponse()
                    response_info = self.helpers.analyzeResponse(response)
                    
                    # Get response body more efficiently
                    body_offset = response_info.getBodyOffset()
                    response_body = self.helpers.bytesToString(response[body_offset:])
                    
                    # Find JavaScript URLs in response using pre-compiled pattern
                    found_urls = js_pattern.findall(response_body)
                    js_urls.update(found_urls)

        except Exception as e:
            self.log("Error processing messages: %s" % str(e))
            return

        if not js_urls:
            self.log("Not a valid JavaScript URL")
            return

        try:
            # Prepare the request with all URLs at once
            data = json.dumps({"urls": list(js_urls)})
            url = "%s?api_key=%s" % (self.api_endpoint, api_key)
            
            # Create and send request
            request = urllib2.Request(url)
            request.add_header('Content-Type', 'application/json')
            request.add_data(data)
            
            # Send request and process response
            response = urllib2.urlopen(request)
            result = json.loads(response.read())
            
            # Log results efficiently
            self.log("\nResults:")
            for r in result.get('results', []):
                status = r.get('status', 'unknown')
                url = r.get('url', 'unknown')
                message = r.get('message', '')
                
                self.log("[%s] %s%s" % (
                    '+' if status == 'success' else '-',
                    url,
                    " - %s" % message if message else ""
                ))
                    
        except Exception as e:
            self.log("Error sending to JSSpy: %s" % str(e)) 
