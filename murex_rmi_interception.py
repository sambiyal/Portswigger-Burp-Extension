# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener, IHttpRequestResponse, IHttpService, ITab, IExtensionStateListener
import threading
import sys
import jarray
from java.net import ServerSocket, Socket, InetSocketAddress
from javax.net.ssl import SSLContext, X509TrustManager, KeyManagerFactory
from java.io import FileInputStream, ByteArrayOutputStream, File
from java.security import KeyStore
from java.lang import String as JString
from javax.swing import JPanel, JLabel, JTextField, JButton, JFileChooser, JTextArea, JScrollPane, BorderFactory, SwingUtilities, JCheckBox, JTabbedPane, JTable
from javax.swing.table import DefaultTableModel
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
        callbacks.registerExtensionStateListener(self)
        
        self.is_running = False
        self.ssl_context = None
        self.server_socket = None
        self.active_connections = []
        self.connections_lock = threading.Lock()
        self.packet_counter = 0
        self.FAKE_HOST = "murex-rmi-bridge"
        
        self.init_ui()
        callbacks.addSuiteTab(self)
        
        self.ui_log("[*] Interceptor extension initialized successfully.")
        self.ui_log("[*] Double-click rows inside 'Packet Inspector' to view payload string cuts.")

    def getTabCaption(self): return "Murex RMI Intercept"
    def getUiComponent(self): return self.main_panel

    def extensionUnloaded(self):
        self.ui_log("[*] Extension unload requested. Cleaning up network resources...")
        self.stop_interceptor()

    def init_ui(self):
        # Base Application Container Window
        self.main_panel = JPanel(BorderLayout())
        
        # Initialize Multi-Tab Layout Interface
        self.tab_container = JTabbedPane()
        
        # ==================== TAB 1: CONTROL DASHBOARD ====================
        tab_control = JPanel(BorderLayout())
        
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
        
        self.chk_rewrite = JCheckBox("Enable Live Server Stream IP Rewriting (S2C Only)", True)
        gbc.gridx = 1; gbc.gridy = 5; gbc.gridwidth = 2; config_panel.add(self.chk_rewrite, gbc)
        
        self.btn_action = JButton("Start Interceptor Listener", actionPerformed=self.btn_action_clicked)
        gbc.gridx = 1; gbc.gridy = 6; gbc.gridwidth = 2; config_panel.add(self.btn_action, gbc)
        
        self.txt_logs = JTextArea(18, 70)
        self.txt_logs.setEditable(False)
        scroll_logs = JScrollPane(self.txt_logs)
        scroll_logs.setBorder(BorderFactory.createTitledBorder("System Engine Status Logs"))
        
        tab_control.add(config_panel, BorderLayout.NORTH)
        tab_control.add(scroll_logs, BorderLayout.CENTER)
        
        # ==================== TAB 2: PACKET INSPECTOR ====================
        tab_inspector = JPanel(BorderLayout())
        
        # Construct traffic visualization data tables
        self.table_model = DefaultTableModel(["ID", "Transmission Context", "Size (Bytes)", "Data Stream Preview"], 0)
        self.packet_table = JTable(self.table_model)
        self.packet_table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN)
        self.packet_table.getColumnModel().getColumn(0).setPreferredWidth(60)
        self.packet_table.getColumnModel().getColumn(1).setPreferredWidth(160)
        self.packet_table.getColumnModel().getColumn(2).setPreferredWidth(100)
        self.packet_table.getColumnModel().getColumn(3).setPreferredWidth(600)
        
        scroll_table = JScrollPane(self.packet_table)
        scroll_table.setBorder(BorderFactory.createTitledBorder("Live Intercepted Cleartext Network Streams"))
        
        btn_clear_table = JButton("Clear Intercepted Traffic Ledger", actionPerformed=self.btn_clear_table_clicked)
        
        tab_inspector.add(scroll_table, BorderLayout.CENTER)
        tab_inspector.add(btn_clear_table, BorderLayout.SOUTH)
        
        # Assemble Tabs into master module container frame layout
        self.tab_container.addTab("Control Dashboard", tab_control)
        self.tab_container.addTab("Packet Inspector", tab_inspector)
        self.main_panel.add(self.tab_container, BorderLayout.CENTER)

    def ui_log(self, message):
        """Thread-safe log utility for system operations"""
        print(message)
        sys.stdout.flush()
        class LogUpdateWorker(vars(threading)['Thread']):
            def run(self):
                try:
                    self.ext.txt_logs.append(self.msg + "\n")
                    self.ext.txt_logs.setCaretPosition(self.ext.txt_logs.getDocument().getLength())
                except: pass
        worker = LogUpdateWorker()
        worker.ext = self
        worker.msg = message
        SwingUtilities.invokeLater(worker)

    def ui_log_packet(self, direction, byte_count, raw_bytes):
        """Injects decrypted packet payloads straight into the GUI ledger grid view"""
        self.packet_counter += 1
        
        # Extract readable string blocks from stream array slice safely
        data_str = JString(raw_bytes, "ISO-8859-1")
        if len(data_str) > 120:
            data_str = data_str.substring(0, 120) + "..."
            
        # Strip control layout bytes to present clear ASCII representations
        clean_chars = []
        for i in range(len(data_str)):
            char_code = ord(data_str[i])
            if 32 <= char_code <= 126:
                clean_chars.append(data_str[i])
            else:
                clean_chars.append(".")
        preview_string = "".join(clean_chars)
        
        class TableUpdateWorker(vars(threading)['Thread']):
            def run(self):
                try:
                    self.ext.table_model.addRow([self.pid, self.direction, self.size, self.preview])
                except: pass
        worker = TableUpdateWorker()
        worker.ext = self
        worker.pid = str(self.packet_counter)
        worker.direction = direction
        worker.size = str(byte_count)
        worker.preview = preview_string
        SwingUtilities.invokeLater(worker)

    def btn_browse_clicked(self, event):
        chooser = JFileChooser()
        if chooser.showOpenDialog(self.main_panel) == JFileChooser.APPROVE_OPTION:
            self.txt_keystore_path.setText(chooser.getSelectedFile().getAbsolutePath())

    def btn_clear_table_clicked(self, event):
        self.table_model.setRowCount(0)
        self.packet_counter = 0
        self.ui_log("[+] Packet Inspector table data wiped cleanly.")

    def btn_action_clicked(self, event):
        if self.is_running: self.stop_interceptor()
        else: self.start_interceptor()

    def start_interceptor(self):
        try:
            self.local_port = int(self.txt_local_port.getText().strip())
            self.target_host = self.txt_target_host.getText().strip()
            self.target_port = int(self.txt_target_port.getText().strip())
            self.keystore_path = self.txt_keystore_path.getText().strip()
            self.keystore_password = self.txt_keystore_password.getText()
            self.should_rewrite = self.chk_rewrite.isSelected()
        except ValueError:
            self.ui_log("[-] Input Exception: Check configurations for non-numerical characters.")
            return

        if not self.init_ssl(): return
        self.is_running = True
        self.btn_action.setText("STOP Interceptor Listener")
        self.toggle_ui_fields(False)
        threading.Thread(target=self.start_local_listener).start()

    def stop_interceptor(self):
        if not self.is_running and not self.server_socket: return
        self.is_running = False
        if self.server_socket:
            try: self.server_socket.close()
            except: pass
            self.server_socket = None
        with self.connections_lock:
            for sock in self.active_connections:
                try: sock.close()
                except: pass
            del self.active_connections[:]
        self.btn_action.setText("Start Interceptor Listener")
        self.toggle_ui_fields(True)
        self.ui_log("[+] Pipeline server socket listeners released.")

    def toggle_ui_fields(self, editable_state):
        self.txt_local_port.setEditable(editable_state)
        self.txt_target_host.setEditable(editable_state)
        self.txt_target_port.setEditable(editable_state)
        self.txt_keystore_path.setEditable(editable_state)
        self.btn_browse.setEnabled(editable_state)
        self.txt_keystore_password.setEditable(editable_state)
        self.chk_rewrite.setEnabled(editable_state)

    def init_ssl(self):
        try:
            ks = KeyStore.getInstance("PKCS12")
            ks.load(FileInputStream(self.keystore_path), list(self.keystore_password))
            kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
            kmf.init(ks, list(self.keystore_password))
            self.ssl_context = SSLContext.getInstance("TLS")
            self.ssl_context.init(kmf.getKeyManagers(), [TrustAllManager()], None)
            return True
        except Exception, e:
            self.ui_log("[-] Cryptographic Context Setup Error: {}".format(str(e)))
            return False

    def start_local_listener(self):
        try:
            self.server_socket = ServerSocket()
            self.server_socket.setReuseAddress(True)
            self.server_socket.bind(InetSocketAddress('127.0.0.1', self.local_port))
            self.ui_log("[+] SUCCESS: Interceptor actively listening on local port {}.".format(self.local_port))
        except Exception, e:
            self.ui_log("[-] Core Socket Bind Failure: {}".format(str(e)))
            self.stop_interceptor()
            return
        
        while self.is_running:
            try:
                client_sock = self.server_socket.accept()
                if not self.is_running: break
                with self.connections_lock: self.active_connections.append(client_sock)
                threading.Thread(target=self.handle_client, args=(client_sock,)).start()
            except Exception: break

    def handle_client(self, client_sock):
        server_sock = None
        try:
            server_sock = Socket()
            with self.connections_lock:
                if not self.is_running: return
                self.active_connections.append(server_sock)
            
            server_sock.connect(InetSocketAddress(self.target_host, self.target_port), 5000)
            
            client_in = client_sock.getInputStream()
            client_out = client_sock.getOutputStream()
            server_in = server_sock.getInputStream()
            server_out = server_sock.getOutputStream()
            
            # Phase 1: Unencrypted Initialization Sequence
            c2s_init = jarray.zeros(7, 'b')
            c2s_read = 0
            while c2s_read < 7:
                res = client_in.read(c2s_init, c2s_read, 7 - c2s_read)
                if res == -1: raise Exception("Client closed connection handshake.")
                c2s_read += res
            
            self.ui_log_packet("HANDSHAKE (CLIENT -> PROXY)", 7, c2s_init)
            server_out.write(c2s_init, 0, 7)
            server_out.flush()
            
            s2c_buf = jarray.zeros(1024, 'b')
            s2c_bytes_read = server_in.read(s2c_buf)
            if s2c_bytes_read == -1: raise Exception("Server closed connection handshake.")
            
            logged_s2c = jarray.zeros(s2c_bytes_read, 'b')
            import java.lang.System
            java.lang.System.arraycopy(s2c_buf, 0, logged_s2c, 0, s2c_bytes_read)
            
            self.ui_log_packet("HANDSHAKE (SERVER -> PROXY)", s2c_bytes_read, logged_s2c)
            client_out.write(s2c_buf, 0, s2c_bytes_read)
            client_out.flush()
            
            self.log_to_burp(c2s_init, logged_s2c, "handshake_initialization")
            
            # Phase 2: Parallel Handshake Upgrades
            self.ui_log("[*] Performing parallel secure session upgrades...")
            ssl_client = self.ssl_context.getSocketFactory().createSocket(client_sock, client_sock.getInetAddress().getHostAddress(), client_sock.getPort(), True)
            ssl_client.setUseClientMode(False)
            
            ssl_server = self.ssl_context.getSocketFactory().createSocket(server_sock, self.target_host, self.target_port, True)
            ssl_server.setUseClientMode(True)
            
            t_client = threading.Thread(target=ssl_client.startHandshake)
            t_server = threading.Thread(target=ssl_server.startHandshake)
            t_client.start()
            t_server.start()
            
            t_client.join(timeout=5)
            t_server.join(timeout=5)
            self.ui_log("[+] Sockets upgraded. Duplex intercept pipes active.")
            
            # Phase 3: Duplex Transmission Pipelines
            t1 = threading.Thread(target=self.stream_pipe, args=(ssl_client, ssl_server, True, client_sock, server_sock))
            t2 = threading.Thread(target=self.stream_pipe, args=(ssl_server, ssl_client, False, client_sock, server_sock))
            t1.start()
            t2.start()
            
        except Exception, e:
            if self.is_running: self.ui_log("[-] Setup Block Aborted: {}".format(str(e)))
            self.cleanup_sockets(client_sock, server_sock)

    def stream_pipe(self, src, dst, is_c2s, raw_client, raw_server):
        buf = jarray.zeros(4096, 'b')
        direction_label = "CLIENT -> SERVER" if is_c2s else "SERVER -> CLIENT"
        endpoint_lbl = "rmi_data_c2s" if is_c2s else "rmi_data_s2c"
        try:
            while self.is_running:
                bytes_read = src.getInputStream().read(buf)
                if bytes_read == -1 or not self.is_running: break
                if bytes_read == 0: continue
                
                out = ByteArrayOutputStream()
                out.write(buf, 0, bytes_read)
                data_bytes = out.toByteArray()
                
                # Dynamic String Token Rewriting Engine
                if not is_c2s and self.should_rewrite:
                    data_str = JString(data_bytes, "ISO-8859-1")
                    if data_str.contains(self.target_host):
                        data_str = data_str.replace(self.target_host, "127.0.0.1")
                        data_bytes = data_str.getBytes("ISO-8859-1")
                
                dst.getOutputStream().write(data_bytes)
                dst.getOutputStream().flush()
                
                # Push decrypted stream event blocks straight to UI ledger grid view rows
                self.ui_log_packet(direction_label, len(data_bytes), data_bytes)
                
                if is_c2s: self.log_to_burp(data_bytes, None, endpoint_lbl)
                else: self.log_to_burp(None, data_bytes, endpoint_lbl)
        except Exception: pass
        finally: self.cleanup_sockets(raw_client, raw_server)

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
        http_req = ("POST /{} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n").format(endpoint, self.FAKE_HOST, len(req_body)) + req_body
        http_res = ("HTTP/1.1 200 OK\r\nServer: Murex-RMI-Bridge\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n").format(len(res_body)) + res_body
        service = CustomHttpService(self.FAKE_HOST, 80, "http")
        self._callbacks.addToHistory(CustomHttpRequestResponse(http_req, http_res, service))

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageInfo.getHttpService().getHost() != self.FAKE_HOST: return
        if messageIsRequest:
            try:
                request_info = self._helpers.analyzeRequest(messageInfo)
                body_offset = request_info.getBodyOffset()
                rmi_payload = messageInfo.getRequest()[body_offset:]
                
                backend_sock = Socket()
                backend_sock.connect(InetSocketAddress(self.target_host, self.target_port), 5000)
                backend_sock.getOutputStream().write(jarray.array([0x4a, 0x52, 0x4d, 0x49, 0x00, 0x01, 0x01], 'b'))
                backend_sock.getOutputStream().flush()
                
                srv_ack = jarray.zeros(1024, 'b')
                backend_sock.getInputStream().read(srv_ack)
                
                ssl_backend = self.ssl_context.getSocketFactory().createSocket(backend_sock, self.target_host, self.target_port, True)
                ssl_backend.setUseClientMode(True)
                ssl_backend.startHandshake()
                
                ssl_backend.getOutputStream().write(rmi_payload)
                ssl_backend.getOutputStream().flush()
                
                backend_sock.setSoTimeout(2000)
                input_stream = ssl_backend.getInputStream()
                res_out = ByteArrayOutputStream()
                buf = jarray.zeros(4096, 'b')
                while True:
                    try:
                        chunk_len = input_stream.read(buf)
                        if chunk_len == -1: break
                        res_out.write(buf, 0, chunk_len)
                        if input_stream.available() == 0: break
                    except Exception: break
                        
                server_rmi_response = res_out.toByteArray()
                http_res = ("HTTP/1.1 200 OK\r\nServer: Murex-RMI-Bridge\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n").format(len(server_rmi_response)) + server_rmi_response
                messageInfo.setResponse(http_res)
            except Exception, e:
                messageInfo.setResponse(("HTTP/1.1 500 Error\r\n\r\n") + "Error executing RMI Replay loop: {}".format(str(e)))
