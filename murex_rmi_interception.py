# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener, IHttpRequestResponse, IHttpService, ITab
import socket
import threading
import jarray
from javax.net.ssl import SSLContext, X509TrustManager, KeyManagerFactory
from java.io import FileInputStream, ByteArrayOutputStream, File
from java.security import KeyStore
from javax.swing import JPanel, JLabel, JTextField, JButton, JFileChooser, JTextArea, JScrollPane, BorderFactory, SwingUtilities
from java.awt import GridBagLayout, GridBagConstraints, Insets, BorderLayout

class CustomHttpService(IHttpService):
    def __init__(self, host, port, protocol):
        self._host = host
        self._port = port
        self._protocol = protocol
    def getHost(self): return self._host
    def getPort(self): return self._port
    def getProtocol(self): return self._protocol

class CustomHttpRequestResponse(IHttpRequestResponse):
    def __init__(self, request, response, httpService):
        self._request = request
        self._response = response
        self._httpService = httpService
    def getRequest(self): return self._request
    def setRequest(self, request): self._request = request
    def getResponse(self): return self._response
    def setResponse(self, response): self._response = response
    def getHttpService(self): return self._httpService
    def setHttpService(self, httpService): self._httpService = httpService
    def getComment(self): return "Decrypted RMI Payload"
    def setComment(self, comment): pass
    def getHighlight(self): return "cyan"
    def setHighlight(self, highlight): pass

class TrustAllManager(X509TrustManager):
    def getAcceptedIssuers(self): return None
    def checkClientTrusted(self, chain, authType): pass
    def checkServerTrusted(self, chain, authType): pass

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("murex_rmi_interception")
        callbacks.registerHttpListener(self)
        
        self.is_running = False
        self.ssl_context = None
        self.FAKE_HOST = "murex-rmi-bridge"
        
        # Initialize User Interface
        self.init_ui()
        callbacks.addSuiteTab(self)
        self.ui_log("[*] murex_rmi_interception UI loaded. Ready to initialize listener.")

    def getTabCaption(self): return "Murex RMI Intercept"
    def getUiComponent(self): return self.main_panel

    def init_ui(self):
        self.main_panel = JPanel(BorderLayout())
        config_panel = JPanel(GridBagLayout())
        config_panel.setBorder(BorderFactory.createTitledBorder("Interceptor Configurations"))
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.fill = GridBagConstraints.HORIZONTAL
        
        # UI Input Fields
        gbc.gridx = 0; gbc.gridy = 0; config_panel.add(JLabel("Local Listen Port:"), gbc)
        self.txt_local_port = JTextField("9101", 10)
        gbc.gridx = 1; gbc.gridy = 0; config_panel.add(self.txt_local_port, gbc)
        
        gbc.gridx = 0; gbc.gridy = 1; config_panel.add(JLabel("Upstream Target Host/IP:"), gbc)
        self.txt_target_host = JTextField("10.100.113.45", 20)
        gbc.gridx = 1; gbc.gridy = 1; config_panel.add(self.txt_target_host, gbc)
        
        gbc.gridx = 0; gbc.gridy = 2; config_panel.add(JLabel("Upstream Target Port:"), gbc)
        self.txt_target_port = JTextField("9101", 10)
        gbc.gridx = 1; gbc.gridy = 2; config_panel.add(self.txt_target_port, gbc)
        
        gbc.gridx = 0; gbc.gridy = 3; config_panel.add(JLabel("Burp CA Path (.p12):"), gbc)
        self.txt_keystore_path = JTextField(r"C:\burp\burpca.p12", 30)
        gbc.gridx = 1; gbc.gridy = 3; config_panel.add(self.txt_keystore_path, gbc)
        self.btn_browse = JButton("Browse...", actionPerformed=self.btn_browse_clicked)
        gbc.gridx = 2; gbc.gridy = 3; config_panel.add(self.btn_browse, gbc)
        
        gbc.gridx = 0; gbc.gridy = 4; config_panel.add(JLabel("KeyStore Password:"), gbc)
        self.txt_keystore_password = JTextField("changeit", 15)
        gbc.gridx = 1; gbc.gridy = 4; config_panel.add(self.txt_keystore_password, gbc)
        
        self.btn_action = JButton("Start Interceptor Listener", actionPerformed=self.btn_action_clicked)
        gbc.gridx = 1; gbc.gridy = 5; gbc.gridwidth = 2; config_panel.add(self.btn_action, gbc)
        
        # Log Window Components
        self.txt_logs = JTextArea(16, 60)
        self.txt_logs.setEditable(False)
        scroll_logs = JScrollPane(self.txt_logs)
        scroll_logs.setBorder(BorderFactory.createTitledBorder("Real-Time Connection Activity Logs"))
        
        self.main_panel.add(config_panel, BorderLayout.NORTH)
        self.main_panel.add(scroll_logs, BorderLayout.CENTER)

    def ui_log(self, message):
        # Ensure thread-safe updates to the Java Swing UI container
        class UpdateLogRunnable(vars(threading)['Thread']):
            def run(self):
                self.txt_logs.append(message + "\n")
                self.txt_logs.setCaretPosition(self.txt_logs.getDocument().getLength())
        SwingUtilities.invokeLater(UpdateLogRunnable())

    def btn_browse_clicked(self, event):
        chooser = JFileChooser()
        if chooser.showOpenDialog(self.main_panel) == JFileChooser.APPROVE_OPTION:
            self.txt_keystore_path.setText(chooser.getSelectedFile().getAbsolutePath())

    def btn_action_clicked(self, event):
        if self.is_running: return
        try:
            self.local_port = int(self.txt_local_port.getText().strip())
            self.target_host = self.txt_target_host.getText().strip()
            self.target_port = int(self.txt_target_port.getText().strip())
            self.keystore_path = self.txt_keystore_path.getText().strip()
            self.keystore_password = self.txt_keystore_password.getText()
        except ValueError:
            self.ui_log("[-] Input Validation Error: Check port configurations.")
            return

        if not self.init_ssl(): return
        
        self.is_running = True
        self.btn_action.setEnabled(False)
        threading.Thread(target=self.start_local_listener).start()

    def init_ssl(self):
        try:
            ks = KeyStore.getInstance("PKCS12")
            ks.load(FileInputStream(self.keystore_path), list(self.keystore_password))
            kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
            kmf.init(ks, list(self.keystore_password))
            self.ssl_context = SSLContext.getInstance("TLS")
            self.ssl_context.init(kmf.getKeyManagers(), [TrustAllManager()], None)
            self.ui_log("[+] SSL decryption layer built from selected Keystore.")
            return True
        except Exception, e:
            self.ui_log("[-] Cryptographic Startup Error: {}".format(str(e)))
            return False

    def start_local_listener(self):
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(('127.0.0.1', self.local_port))
            server.listen(15)
            self.ui_log("[+] Core proxy engine actively listening on 127.0.0.1:{}...".format(self.local_port))
        except Exception, e:
            self.ui_log("[-] Port Bind Failure: {}".format(str(e)))
            self.is_running = False
            return
        
        while True:
            client_sock, addr = server.accept()
            self.ui_log("[*] Incoming client connection accepted from: {}:{}".format(addr[0], addr[1]))
            threading.Thread(target=self.handle_client, args=(client_sock,)).start()

    def handle_client(self, client_sock):
        try:
            self.ui_log("[*] Establishing link to upstream target server at {}:{}...".format(self.target_host, self.target_port))
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.connect((self.target_host, self.target_port))
            
            # Phase 1: Exchange baseline plain-text 7-byte JRMI handshakes
            self.ui_log("[*] Intercepting plain-text JRMI handshake header...")
            c2s_init = client_sock.recv(7)
            self.ui_log("[C2S] Plain Handshake Header: '{}'".format(c2s_init.encode('string_escape')))
            server_sock.sendall(c2s_init)
            
            s2c_init = server_sock.recv(7)
            self.ui_log("[S2C] Server Handshake Reply: '{}'".format(s2c_init.encode('string_escape')))
            client_sock.sendall(s2c_init)
            
            self.log_to_burp(c2s_init, s2c_init, "handshake_initialization")
            
            # Phase 2: Dynamic Sockets upgrade to SSL/TLS mid-stream (StartTLS Execution)
            self.ui_log("[*] Initiating mid-stream cryptographic upgrade (StartTLS encapsulation)...")
            ssl_client = self.ssl_context.getSocketFactory().createSocket(client_sock, client_sock.getInetAddress().getHostAddress(), client_sock.getPort(), True)
            ssl_client.setUseClientMode(False)
            ssl_client.startHandshake()
            self.ui_log("[+] Client TLS Handshake completed successfully.")
            
            ssl_server = self.ssl_context.getSocketFactory().createSocket(server_sock, self.target_host, self.target_port, True)
            ssl_server.setUseClientMode(True)
            ssl_server.startHandshake()
            self.ui_log("[+] Upstream Server TLS Handshake completed successfully.")
            
            # Phase 3: Launch streaming pipelines using native Java byte arrays to eliminate blocking
            self.ui_log("[+] Sockets upgraded. Initializing real-time data streaming loops.")
            t1 = threading.Thread(target=self.stream_pipe, args=(ssl_client, ssl_server, True))
            t2 = threading.Thread(target=self.stream_pipe, args=(ssl_server, ssl_client, False))
            t1.start()
            t2.start()
            
        except Exception, e:
            self.ui_log("[-] Connection pipeline tracking broken: {}".format(str(e)))

    def stream_pipe(self, src, dst, is_c2s):
        # Using a native Java byte array prevents Jython from blocking indefinitely on read()
        buf = jarray.zeros(4096, 'b')
        direction = "C2S" if is_c2s else "S2C"
        try:
            while True:
                bytes_read = src.getInputStream().read(buf)
                if bytes_read == -1:
                    self.ui_log("[*] Connection stream closed by remote endpoint ({}).".format(direction))
                    break
                if bytes_read == 0:
                    continue
                
                # Extract the exact slice of data read from the buffer
                out = ByteArrayOutputStream()
                out.write(buf, 0, bytes_read)
                data_bytes = out.toByteArray()
                
                # Forward data to destination
                dst.getOutputStream().write(buf, 0, bytes_read)
                dst.getOutputStream().flush()
                
                self.ui_log("[Data Transfer] {} -> Forwarded {} bytes".format(direction, bytes_read))
                
                if is_c2s:
                    self.log_to_burp(data_bytes, None, "rmi_data_c2s")
                else:
                    self.log_to_burp(None, data_bytes, "rmi_data_s2c")
        except Exception, e:
            self.ui_log("[-] Active stream pipe exception ({}): {}".format(direction, str(e)))
        finally:
            try: src.close()
            except: pass
            try: dst.close()
            except: pass

    def log_to_burp(self, request_bytes, response_bytes, endpoint):
        req_body = request_bytes if request_bytes else b""
        res_body = response_bytes if response_bytes else b""
        
        http_req = (
            "POST /{} HTTP/1.1\r\n"
            "Host: {}\r\n"
            "Content-Type: application/octet-stream\r\n"
            "Content-Length: {}\r\n\r\n"
        ).format(endpoint, self.FAKE_HOST, len(req_body)) + req_body
        
        http_res = (
            "HTTP/1.1 200 OK\r\n"
            "Server: Murex-RMI-Bridge\r\n"
            "Content-Type: application/octet-stream\r\n"
            "Content-Length: {}\r\n\r\n"
        ).format(len(res_body)) + res_body
        
        service = CustomHttpService(self.FAKE_HOST, 80, "http")
        item = CustomHttpRequestResponse(http_req, http_res, service)
        self._callbacks.addToHistory(item)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageInfo.getHttpService().getHost() != self.FAKE_HOST: return
        if messageIsRequest:
            try:
                request_info = self._helpers.analyzeRequest(messageInfo)
                req_bytes = messageInfo.getRequest()
                body_offset = request_info.getBodyOffset()
                rmi_payload = req_bytes[body_offset:]
                
                backend_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                backend_sock.connect((self.target_host, self.target_port))
                
                backend_sock.sendall(b"JRMI\x00\x01\x01")
                backend_sock.recv(7)
                
                ssl_backend = self.ssl_context.getSocketFactory().createSocket(backend_sock, self.target_host, self.target_port, True)
                ssl_backend.setUseClientMode(True)
                ssl_backend.startHandshake()
                
                ssl_backend.getOutputStream().write(rmi_payload)
                ssl_backend.getOutputStream().flush()
                
                backend_sock.setSoTimeout(2000)
                input_stream = ssl_backend.getInputStream()
                
                res_out = ByteArrayOutputStream()
                while True:
                    try:
                        chunk = input_stream.read()
                        if chunk == -1: break
                        res_out.write(chunk)
                        if input_stream.available() == 0: break
                    except Exception: break
                        
                server_rmi_response = res_out.toByteArray()
                http_res = (
                    "HTTP/1.1 200 OK\r\n"
                    "Server: Murex-RMI-Bridge\r\n"
                    "Content-Type: application/octet-stream\r\n"
                    "Content-Length: {}\r\n\r\n"
                ).format(len(server_rmi_response)) + server_rmi_response
                messageInfo.setResponse(http_res)
            except Exception, e:
                err_msg = "Error executing RMI Replay loop: {}".format(str(e))
                http_err = ( "HTTP/1.1 500 Error\r\n\r\n" ) + err_msg
                messageInfo.setResponse(http_err)
