# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener, IHttpRequestResponse, IHttpService, ITab, IExtensionStateListener
import threading
import sys
import jarray
import datetime
import java.awt
import java.lang.System
from java.net import ServerSocket, Socket, InetSocketAddress
from javax.net.ssl import SSLContext, X509TrustManager, KeyManagerFactory
from java.io import FileInputStream, ByteArrayOutputStream, File, PushbackInputStream
from java.security import KeyStore
from java.lang import String as JString
from javax.swing import JPanel, JLabel, JTextField, JButton, JFileChooser, JTextArea, JScrollPane, BorderFactory, SwingUtilities, JCheckBox, JTabbedPane, JTable, JSplitPane
from javax.swing.table import DefaultTableModel
from javax.swing.event import ListSelectionListener
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

class TableSelectionHandler(ListSelectionListener):
    def __init__(self, extender):
        self.extender = extender
    def valueChanged(self, event):
        if not event.getValueIsAdjusting():
            selected_row = self.extender.packet_table.getSelectedRow()
            if selected_row != -1:
                try:
                    packet_id = int(self.extender.table_model.getValueAt(selected_row, 0))
                    with self.extender.data_lock:
                        if packet_id <= len(self.extender.packet_payloads):
                            self.extender.txt_packet_details.setText(self.extender.packet_payloads[packet_id - 1])
                except Exception:
                    pass

class BurpExtender(IBurpExtender, IHttpListener, ITab, IExtensionStateListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("murex_rmi_interception")
        callbacks.registerHttpListener(self)
        callbacks.registerExtensionStateListener(self)
        
        self.is_running = False
        self.ssl_context = None
        self.server_sockets = []
        self.active_connections = []
        self.connections_lock = threading.Lock()
        
        # Deep packet inspection tracking lists
        self.packet_payloads = []
        self.data_lock = threading.Lock()
        self.packet_counter = 0
        self.FAKE_HOST = "murex-rmi-bridge"
        
        self.init_ui()
        callbacks.addSuiteTab(self)
        
        self.ui_log("[*] Multi-Port Decryption Engine Loaded Successfully.")
        self.ui_log("[*] Configuration Guide: Specify multiple ports separated by commas (e.g. 9101, 9091).")

    def getTabCaption(self): return "Murex RMI Intercept"
    def getUiComponent(self): return self.main_panel

    def extensionUnloaded(self):
        self.ui_log("[*] Extension unload requested. Purging multi-port binding map...")
        self.stop_interceptor()

    def init_ui(self):
        self.main_panel = JPanel(BorderLayout())
        self.tab_container = JTabbedPane()
        
        # ==================== TAB 1: CONTROL DASHBOARD ====================
        tab_control = JPanel(BorderLayout())
        config_panel = JPanel(GridBagLayout())
        config_panel.setBorder(BorderFactory.createTitledBorder("Universal Pipeline Routing Settings"))
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.fill = GridBagConstraints.HORIZONTAL
        
        gbc.gridx = 0; gbc.gridy = 0; config_panel.add(JLabel("Local Listen Ports (List):"), gbc)
        self.txt_local_port = JTextField("9101, 9091", 15)
        gbc.gridx = 1; gbc.gridy = 0; config_panel.add(self.txt_local_port, gbc)
        
        gbc.gridx = 0; gbc.gridy = 1; config_panel.add(JLabel("Upstream Target Host/IP:"), gbc)
        self.txt_target_host = JTextField("10.100.113.45", 20)
        gbc.gridx = 1; gbc.gridy = 1; config_panel.add(self.txt_target_host, gbc)
        
        gbc.gridx = 0; gbc.gridy = 2; config_panel.add(JLabel("Burp CA Path (.p12):"), gbc)
        self.txt_keystore_path = JTextField(r"C:\BurpTesting\burpca.p12", 30)
        gbc.gridx = 1; gbc.gridy = 2; config_panel.add(self.txt_keystore_path, gbc)
        self.btn_browse = JButton("Browse...", actionPerformed=self.btn_browse_clicked)
        gbc.gridx = 2; gbc.gridy = 2; config_panel.add(self.btn_browse, gbc)
        
        gbc.gridx = 0; gbc.gridy = 3; config_panel.add(JLabel("KeyStore Password:"), gbc)
        self.txt_keystore_password = JTextField("changeit", 15)
        gbc.gridx = 1; gbc.gridy = 3; config_panel.add(self.txt_keystore_password, gbc)
        
        self.chk_rewrite = JCheckBox("Enable Dynamic Server Metadata Address Rewriting (S2C Only)", True)
        gbc.gridx = 1; gbc.gridy = 4; gbc.gridwidth = 2; config_panel.add(self.chk_rewrite, gbc)
        
        self.btn_action = JButton("Start Interceptor Listener", actionPerformed=self.btn_action_clicked)
        gbc.gridx = 1; gbc.gridy = 5; gbc.gridwidth = 2; config_panel.add(self.btn_action, gbc)
        
        self.txt_logs = JTextArea(18, 70)
        self.txt_logs.setEditable(False)
        scroll_logs = JScrollPane(self.txt_logs)
        scroll_logs.setBorder(BorderFactory.createTitledBorder("System Engine Status Logs (Verbose Mode)"))
        
        tab_control.add(config_panel, BorderLayout.NORTH)
        tab_control.add(scroll_logs, BorderLayout.CENTER)
        
        # ==================== TAB 2: PACKET INSPECTOR ====================
        tab_inspector = JPanel(BorderLayout())
        
        self.table_model = DefaultTableModel(["ID", "Network Context Route", "Size (Bytes)", "Summary Payload Preview"], 0)
        self.packet_table = JTable(self.table_model)
        self.packet_table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN)
        self.packet_table.getColumnModel().getColumn(0).setPreferredWidth(60)
        self.packet_table.getColumnModel().getColumn(1).setPreferredWidth(200)
        self.packet_table.getColumnModel().getColumn(2).setPreferredWidth(100)
        self.packet_table.getColumnModel().getColumn(3).setPreferredWidth(550)
        
        # Click selection trigger
        self.packet_table.getSelectionModel().addListSelectionListener(TableSelectionHandler(self))
        scroll_table = JScrollPane(self.packet_table)
        scroll_table.setBorder(BorderFactory.createTitledBorder("Live Intercepted Cleartext Network Streams"))
        
        self.txt_packet_details = JTextArea()
        self.txt_packet_details.setEditable(False)
        self.txt_packet_details.setFont(java.awt.Font("Monospaced", java.awt.Font.PLAIN, 12))
        scroll_details = JScrollPane(self.txt_packet_details)
        scroll_details.setBorder(BorderFactory.createTitledBorder("Full Request / Response Hex & String Inspector Pane"))
        
        # Split layout pane view
        split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT, scroll_table, scroll_details)
        split_pane.setDividerLocation(220)
        
        btn_clear_table = JButton("Clear Intercepted Traffic Ledger", actionPerformed=self.btn_clear_table_clicked)
        
        tab_inspector.add(split_pane, BorderLayout.CENTER)
        tab_inspector.add(btn_clear_table, BorderLayout.SOUTH)
        
        self.tab_container.addTab("Control Dashboard", tab_control)
        self.tab_container.addTab("Packet Inspector", tab_inspector)
        self.main_panel.add(self.tab_container, BorderLayout.CENTER)

    def ui_log(self, message):
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

    def generate_hex_dump(self, src):
        if not src: return ""
        lines = []
        byte_list = [b & 0xFF for b in src]
        for i in range(0, len(byte_list), 16):
            chunk = byte_list[i:i+16]
            hex_part = " ".join("{:02X}".format(b) for b in chunk)
            if len(chunk) < 16:
                hex_part += " " * (3 * (16 - len(chunk)))
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            lines.append("{:04X}   {}   {}".format(i, hex_part, ascii_part))
        return "\n".join(lines)

    def ui_log_packet(self, direction, byte_count, raw_bytes):
        self.packet_counter += 1
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        
        try:
            j_str = JString(raw_bytes, "ISO-8859-1")
            display_str = j_str.substring(0, 120) + "..." if j_str.length() > 120 else j_str
            clean_chars = [chr(display_str.charAt(i)) if 32 <= display_str.charAt(i) <= 126 else "." for i in range(display_str.length())]
            preview_string = "".join(clean_chars)
        except Exception, e:
            preview_string = "[Payload Parsing Issue: {}]".format(str(e))
            
        # Compile master hex representation database
        dump_view = self.generate_hex_dump(raw_bytes)
        detailed_breakdown = (
            "============================================================\n"
            " TRANSACTION PAYLOAD INSPECTION VISUALIZER                  \n"
            "============================================================\n"
            "Packet Ledger ID:  {}\n"
            "Event Timestamp:   {}\n"
            "Routing Context:   {}\n"
            "Payload Segment:   {} Bytes\n\n"
            "------------------- CLEAR-STREAM RAW DATA -------------------\n"
            "{}"
        ).format(self.packet_counter, timestamp, direction, byte_count, dump_view)
        
        with self.data_lock:
            self.packet_payloads.append(detailed_breakdown)
        
        class TableUpdateWorker(vars(threading)['Thread']):
            def run(self):
                try: self.ext.table_model.addRow([self.pid, self.direction, self.size, self.preview])
                except: pass
        worker = TableUpdateWorker()
        worker.ext = self
        worker.pid = str(self.packet_counter)
        worker.direction = direction
        worker.size = str(byte_count)
        worker.preview = preview_string
        SwingUtilities.invokeLater(worker)

    def get_safe_length(self, byte_array):
        if byte_array is None: return 0
        try: return len(byte_array)
        except:
            if hasattr(byte_array, 'length'): return byte_array.length
            return 0

    def btn_browse_clicked(self, event):
        chooser = JFileChooser()
        if chooser.showOpenDialog(self.main_panel) == JFileChooser.APPROVE_OPTION:
            self.txt_keystore_path.setText(chooser.getSelectedFile().getAbsolutePath())

    def btn_clear_table_clicked(self, event):
        self.table_model.setRowCount(0)
        self.packet_counter = 0
        with self.data_lock:
            del self.packet_payloads[:]
        self.txt_packet_details.setText("")
        self.ui_log("[+] Packet Inspector grid array cleared successfully.")

    def btn_action_clicked(self, event):
        if self.is_running: self.stop_interceptor()
        else: self.start_interceptor()

    def start_interceptor(self):
        ports_str = self.txt_local_port.getText().strip()
        try:
            self.ports = [int(p.strip()) for p in ports_str.split(",")]
            self.target_host = self.txt_target_host.getText().strip()
            self.keystore_path = self.txt_keystore_path.getText().strip()
            self.keystore_password = self.txt_keystore_password.getText()
            self.should_rewrite = self.chk_rewrite.isSelected()
        except Exception:
            self.ui_log("[-] Input Exception: Check port specifications for syntax formatting defects.")
            return

        if not self.init_ssl(): return
        self.is_running = True
        self.btn_action.setText("STOP Interceptor Listener")
        self.toggle_ui_fields(False)
        
        # Fire isolated listener thread workers for each individual mapped port
        self.server_sockets = []
        for port in self.ports:
            t = threading.Thread(target=self.listen_on_port, args=(port,))
            t.daemon = True
            t.start()

    def stop_interceptor(self):
        if not self.is_running: return
        self.is_running = False
        
        with self.connections_lock:
            if hasattr(self, 'server_sockets') and self.server_sockets:
                for ssock in self.server_sockets:
                    try: ssock.close()
                    except: pass
                self.server_sockets = []
            
            for sock in self.active_connections:
                try: sock.close()
                except: pass
            del self.active_connections[:]
            
        self.btn_action.setText("Start Interceptor Listener")
        self.toggle_ui_fields(True)
        self.ui_log("[+] All local port sockets released. System returned to DORMANT status.")

    def toggle_ui_fields(self, editable_state):
        self.txt_local_port.setEditable(editable_state)
        self.txt_target_host.setEditable(editable_state)
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
            self.ui_log("[-] Cryptographic Context Failure: {}".format(str(e)))
            return False

    def listen_on_port(self, port):
        try:
            ssock = ServerSocket()
            ssock.setReuseAddress(True)
            ssock.bind(InetSocketAddress('127.0.0.1', port))
            with self.connections_lock:
                self.server_sockets.append(ssock)
            self.ui_log("[+] Active listener bound to loopback interface on port {}.".format(port))
            
            while self.is_running:
                client_sock = ssock.accept()
                if not self.is_running: break
                self.ui_log("[*] Connection incoming on port {} from client system.".format(port))
                with self.connections_lock:
                    self.active_connections.append(client_sock)
                t = threading.Thread(target=self.handle_client, args=(client_sock, port))
                t.daemon = True
                t.start()
        except Exception, e:
            if self.is_running:
                self.ui_log("[-] Port {} Binding Fault: {}".format(port, str(e)))

    def handle_client(self, client_sock, port):
        server_sock = None
        try:
            server_sock = Socket()
            with self.connections_lock:
                if not self.is_running: return
                self.active_connections.append(server_sock)
            
            server_sock.connect(InetSocketAddress(self.target_host, port), 5000)
            self.ui_log("[+] Connected to backend server address on matching data port {}.".format(port))
            
            # Wrap input channels with PushbackInputStream to look inside handshake context dynamically
            client_in = PushbackInputStream(client_sock.getInputStream(), 16)
            client_out = client_sock.getOutputStream()
            server_in = PushbackInputStream(server_sock.getInputStream(), 16)
            server_out = server_sock.getOutputStream()
            
            # Inspect first 4 bytes to check for unencrypted JRMI magic
            peek_buf = jarray.zeros(4, 'b')
            peeked_len = client_in.read(peek_buf, 0, 4)
            is_jrmi = False
            
            if peeked_len == 4:
                if peek_buf[0] == 0x4a and peek_buf[1] == 0x52 and peek_buf[2] == 0x4d and peek_buf[3] == 0x49:
                    is_jrmi = True
                client_in.unread(peek_buf, 0, peeked_len) # Restore buffer array alignment
                
            if is_jrmi:
                self.ui_log("[Port {}] Handshake Match: StartTLS protocol detected.".format(port))
                c2s_init = jarray.zeros(7, 'b')
                c2s_read = 0
                while c2s_read < 7:
                    res = client_in.read(c2s_init, c2s_read, 7 - c2s_read)
                    if res == -1: raise Exception("Client closed connection handshake parameters.")
                    c2s_read += res
                
                self.ui_log_packet("PLAIN HANDSHAKE (CLIENT -> SERVER) [Port {}]".format(port), 7, c2s_init)
                server_out.write(c2s_init, 0, 7)
                server_out.flush()
                
                s2c_buf = jarray.zeros(1024, 'b')
                s2c_bytes_read = server_in.read(s2c_buf)
                if s2c_bytes_read == -1: raise Exception("Server closed configuration stream mapping.")
                
                logged_s2c = jarray.zeros(s2c_bytes_read, 'b')
                java.lang.System.arraycopy(s2c_buf, 0, logged_s2c, 0, s2c_bytes_read)
                
                self.ui_log_packet("PLAIN HANDSHAKE (SERVER -> CLIENT) [Port {}]".format(port), s2c_bytes_read, logged_s2c)
                client_out.write(s2c_buf, 0, s2c_bytes_read)
                client_out.flush()
                
                self.log_to_burp(c2s_init, logged_s2c, "handshake_{}".format(port))
            else:
                self.ui_log("[Port {}] Protocol Match: Implicit Cryptography context detected.".format(port))
                
            # Execute cryptographic wrappers natively inside the JVM context
            ssl_client = self.ssl_context.getSocketFactory().createSocket(client_sock, client_in, True)
            ssl_client.setUseClientMode(False)
            ssl_server = self.ssl_context.getSocketFactory().createSocket(server_sock, server_in, True)
            ssl_server.setUseClientMode(True)
            
            t_client = threading.Thread(target=ssl_client.startHandshake)
            t_server = threading.Thread(target=ssl_server.startHandshake)
            t_client.start()
            t_server.start()
            
            t_client.join(timeout=5)
            t_server.join(timeout=5)
            self.ui_log("[+] [Port {}] SSL/TLS dynamic session handshake verification completed.".format(port))
            
            t1 = threading.Thread(target=self.stream_pipe, args=(ssl_client, ssl_server, True, client_sock, server_sock, port))
            t2 = threading.Thread(target=self.stream_pipe, args=(ssl_server, ssl_client, False, client_sock, server_sock, port))
            t1.start()
            t2.start()
            
        except Exception, e:
            if self.is_running: self.ui_log("[-] [Port {}] Active Pipeline Terminated: {}".format(port, str(e)))
            self.cleanup_sockets(client_sock, server_sock)

    def stream_pipe(self, src, dst, is_c2s, raw_client, raw_server, port):
        buf = jarray.zeros(4096, 'b')
        direction_label = "CLIENT -> SERVER" if is_c2s else "SERVER -> CLIENT"
        endpoint_lbl = "rmi_c2s_{}".format(port) if is_c2s else "rmi_s2c_{}".format(port)
        try:
            while self.is_running:
                bytes_read = src.getInputStream().read(buf)
                if bytes_read == -1 or not self.is_running: break
                if bytes_read == 0: continue
                
                out = ByteArrayOutputStream()
                out.write(buf, 0, bytes_read)
                data_bytes = out.toByteArray()
                
                if not is_c2s and self.should_rewrite:
                    data_str = JString(data_bytes, "ISO-8859-1")
                    if data_str.contains(self.target_host):
                        data_str = data_str.replace(self.target_host, "127.0.0.1")
                        data_bytes = data_str.getBytes("ISO-8859-1")
                
                dst.getOutputStream().write(data_bytes)
                dst.getOutputStream().flush()
                
                computed_len = self.get_safe_length(data_bytes)
                self.ui_log_packet("{} [Port {}]".format(direction_label, port), computed_len, data_bytes)
                
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
        req_len = self.get_safe_length(req_body)
        
        http_req = ("POST /{} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n").format(endpoint, self.FAKE_HOST, req_len) + req_body
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
                backend_sock.connect(InetSocketAddress(self.target_host, 9101), 5000)
                backend_sock.getOutputStream().write(jarray.array([0x4a, 0x52, 0x4d, 0x49, 0x00, 0x01, 0x01], 'b'))
                backend_sock.getOutputStream().flush()
                
                srv_ack = jarray.zeros(1024, 'b')
                backend_sock.getInputStream().read(srv_ack)
                
                ssl_backend = self.ssl_context.getSocketFactory().createSocket(backend_sock, self.target_host, 9101, True)
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
