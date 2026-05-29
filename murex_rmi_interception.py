# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener, IHttpRequestResponse, IHttpService, ITab, IExtensionStateListener
import socket
import threading
import sys
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

class BurpExtender(IBurpExtender, IHttpListener, ITab, IExtensionStateListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("murex_rmi_interception")
        callbacks.registerHttpListener(self)
        
        # Register the state listener to handle clean unloads/reloads
        callbacks.registerExtensionStateListener(self)
        
        # Ensure default state is completely stopped on initial load
        self.is_running = False
        self.ssl_context = None
        self.server_socket = None
        self.active_connections = []
        self.connections_lock = threading.Lock()
        self.FAKE_HOST = "murex-rmi-bridge"
        
        self.init_ui()
        callbacks.addSuiteTab(self)
        
        self.ui_log("[*] Extension Loaded in DORMANT state. Sockets are unbound.")
        self.ui_log("[*] Click 'Start Interceptor Listener' below to initiate the proxy pipeline.")

    def getTabCaption(self): return "Murex RMI Intercept"
    def getUiComponent(self): return self.main_panel

    def extensionUnloaded(self):
        """Burp API override: Triggers instantly if the user removes or reloads the extension"""
        print("[*] Extension unload event detected. Cleaning up socket space...")
        self.stop_interceptor()

    def init_ui(self):
        self.main_panel = JPanel(BorderLayout())
        config_panel = JPanel(GridBagLayout())
        config_panel.setBorder(BorderFactory.createTitledBorder("Interceptor Configurations"))
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.fill = GridBagConstraints.HORIZONTAL
        
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
        self.txt_keystore_path = JTextField(r"C:\BurpTesting\burpca.p12", 30)
        gbc.gridx = 1; gbc.gridy = 3; config_panel.add(self.txt_keystore_path, gbc)
        self.btn_browse = JButton("Browse...", actionPerformed=self.btn_browse_clicked)
        gbc.gridx = 2; gbc.gridy = 3; config_panel.add(self.btn_browse, gbc)
        
        gbc.gridx = 0; gbc.gridy = 4; config_panel.add(JLabel("KeyStore Password:"), gbc)
        self.txt_keystore_password = JTextField("changeit", 15)
        gbc.gridx = 1; gbc.gridy = 4; config_panel.add(self.txt_keystore_password, gbc)
        
        self.btn_action = JButton("Start Interceptor Listener", actionPerformed=self.btn_action_clicked)
        gbc.gridx = 1; gbc.gridy = 5; gbc.gridwidth = 2; config_panel.add(self.btn_action, gbc)
        
        self.txt_logs = JTextArea(20, 70)
        self.txt_logs.setEditable(False)
        scroll_logs = JScrollPane(self.txt_logs)
        scroll_logs.setBorder(BorderFactory.createTitledBorder("Verbose Engine Stream Activity Logs"))
        
        self.main_panel.add(config_panel, BorderLayout.NORTH)
        self.main_panel.add(scroll_logs, BorderLayout.CENTER)

    def ui_log(self, message):
        print(message)
        sys.stdout.flush()
        try:
            def append_text():
                self.txt_logs.append(message + "\n")
                self.txt_logs.setCaretPosition(self.txt_logs.getDocument().getLength())
            SwingUtilities.invokeLater(append_text)
        except Exception: pass

    def btn_browse_clicked(self, event):
        chooser = JFileChooser()
        if chooser.showOpenDialog(self.main_panel) == JFileChooser.APPROVE_OPTION:
            self.txt_keystore_path.setText(chooser.getSelectedFile().getAbsolutePath())

    def btn_action_clicked(self, event):
        if self.is_running:
            self.stop_interceptor()
        else:
            self.start_interceptor()

    def start_interceptor(self):
        self.ui_log("[*] Booting pipeline components dynamically...")
        try:
            self.local_port = int(self.txt_local_port.getText().strip())
            self.target_host = self.txt_target_host.getText().strip()
            self.target_port = int(self.txt_target_port.getText().strip())
            self.keystore_path = self.txt_keystore_path.getText().strip()
            self.keystore_password = self.txt_keystore_password.getText()
        except ValueError:
            self.ui_log("[-] Input Exception: Port entries must be integers.")
            return

        if not self.init_ssl(): return
        
        self.is_running = True
        self.btn_action.setText("STOP Interceptor Listener")
        self.toggle_ui_fields(False)
        
        # Thread handles runtime execution ONLY after this explicit button action event
        threading.Thread(target=self.start_local_listener).start()

    def stop_interceptor(self):
        if not self.is_running and not self.server_socket:
            return
            
        self.ui_log("[*] Stopping proxy and freeing bound ports...")
        self.is_running = False
        
        if self.server_socket:
            try:
                self.server_socket.close()
                self.ui_log("[+] Main listening socket closed.")
            except Exception, e:
                self.ui_log("[-] Error closing listener: {}".format(str(e)))
            self.server_socket = None
        
        with self.connections_lock:
            if self.active_connections:
                self.ui_log("[*] Terminating {} running stream tunnels...".format(len(self.active_connections)))
                for sock in self.active_connections:
                    try: sock.close()
                    except: pass
                del self.active_connections[:]
        
        self.btn_action.setText("Start Interceptor Listener")
        self.toggle_ui_fields(True)
        self.ui_log("[+] Status: Stopped and dormant.")

    def toggle_ui_fields(self, editable_state):
        self.txt_local_port.setEditable(editable_state)
        self.txt_target_host.setEditable(editable_state)
        self.txt_target_port.setEditable(editable_state)
        self.txt_keystore_path.setEditable(editable_state)
        self.btn_browse.setEnabled(editable_state)
        self.txt_keystore_password.setEditable(editable_state)

    def init_ssl(self):
        if not File(self.keystore_path).exists():
            self.ui_log("[-] Critical Error: KeyStore file path is invalid.")
            return False
        try:
            ks = KeyStore.getInstance("PKCS12")
            ks.load(FileInputStream(self.keystore_path), list(self.keystore_password))
            kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
            kmf.init(ks, list(self.keystore_password))
            self.ssl_context = SSLContext.getInstance("TLS")
            self.ssl_context.init(kmf.getKeyManagers(), [TrustAllManager()], None)
            return True
        except Exception, e:
            self.ui_log("[-] SSL initialization defect: {}".format(str(e)))
            return False

    def start_local_listener(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('127.0.0.1', self.local_port))
            self.server_socket.listen(15)
            self.ui_log("[+] SUCCESS: Interceptor proxy now listening on 127.0.0.1:{}.".format(self.local_port))
        except Exception, e:
            if self.is_running:
                self.ui_log("[-] Bind Failure: Port {} might be in use. Clean up other extensions.".format(self.local_port))
                self.stop_interceptor()
            return
        
        while self.is_running:
            try:
                client_sock, addr = self.server_socket.accept()
                if not self.is_running: break
                
                self.ui_log("[*] Connection incoming from client: {}:{}".format(addr[0], addr[1]))
                with self.connections_lock:
                    self.active_connections.append(client_sock)
                threading.Thread(target=self.handle_client, args=(client_sock,)).start()
            except Exception:
                break

    def handle_client(self, client_sock):
        server_sock = None
        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            with self.connections_lock:
                if not self.is_running: return
                self.active_connections.append(server_sock)
                
            server_sock.connect((self.target_host, self.target_port))
            
            c2s_init = client_sock.recv(7)
            if not c2s_init or not self.is_running: return
            server_sock.sendall(c2s_init)
            
            s2c_init = server_sock.recv(7)
            if not s2c_init or not self.is_running: return
            client_sock.sendall(s2c_init)
            
            self.log_to_burp(c2s_init, s2c_init, "handshake_initialization")
            
            ssl_client = self.ssl_context.getSocketFactory().createSocket(client_sock, client_sock.getInetAddress().getHostAddress(), client_sock.getPort(), True)
            ssl_client.setUseClientMode(False)
            ssl_client.startHandshake()
            
            ssl_server = self.ssl_context.getSocketFactory().createSocket(server_sock, self.target_host, self.target_port, True)
            ssl_server.setUseClientMode(True)
            ssl_server.startHandshake()
            
            self.ui_log("[+] Handshakes synchronized. Duplex tunnels active.")
            
            t1 = threading.Thread(target=self.stream_pipe, args=(ssl_client, ssl_server, True, client_sock, server_sock))
            t2 = threading.Thread(target=self.stream_pipe, args=(ssl_server, ssl_client, False, client_sock, server_sock))
            t1.start()
            t2.start()
            
        except Exception, e:
            if self.is_running:
                self.ui_log("[-] Connection tunnel dropped: {}".format(str(e)))
            self.cleanup_sockets(client_sock, server_sock)

    def stream_pipe(self, src, dst, is_c2s, raw_client, raw_server):
        buf = jarray.zeros(4096, 'b')
        direction = "CLIENT -> SERVER" if is_c2s else "SERVER -> CLIENT"
        endpoint_lbl = "rmi_data_c2s" if is_c2s else "rmi_data_s2c"
        
        try:
            while self.is_running:
                bytes_read = src.getInputStream().read(buf)
                if bytes_read == -1 or not self.is_running: break
                if bytes_read == 0: continue
                
                out = ByteArrayOutputStream()
                out.write(buf, 0, bytes_read)
                data_bytes = out.toByteArray()
                
                dst.getOutputStream().write(buf, 0, bytes_read)
                dst.getOutputStream().flush()
                
                self.ui_log("[TRANSMISSION] {} | Intercepted: {} bytes".format(direction, bytes_read))
                
                if is_c2s:
                    self.log_to_burp(data_bytes, None, endpoint_lbl)
                else:
                    self.log_to_burp(None, data_bytes, endpoint_lbl)
        except Exception: pass
        finally:
            self.cleanup_sockets(raw_client, raw_server)

    def cleanup_sockets(self, s1, s2):
        try: s1.close()
        except: pass
        try: s2.close()
        except: pass
        with self.connections_lock:
            if s1 in self.active_connections: self.active_connections.remove(s1)
            if s2 in self.active_connections: self.active_connections.remove(s2)

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
