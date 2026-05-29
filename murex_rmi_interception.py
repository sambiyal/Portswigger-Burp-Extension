# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener, IHttpRequestResponse, IHttpService, ITab, IExtensionStateListener
import threading
import sys
import jarray
import datetime
import java.awt
from java.net import ServerSocket, Socket, InetSocketAddress
from javax.net.ssl import SSLContext, X509TrustManager, KeyManagerFactory
from java.io import FileInputStream, ByteArrayOutputStream, File
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
                except Exception: pass

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
        
        self.packet_payloads = []
        self.data_lock = threading.Lock()
        self.packet_counter = 0
        self.FAKE_HOST = "murex-rmi-bridge"
        
        self.init_ui()
        callbacks.addSuiteTab(self)
        self.ui_log("[*] Interceptor loaded. Ready to trace StartTLS transitions.")

    def getTabCaption(self): return "Murex RMI Intercept"
    def getUiComponent(self): return self.main_panel

    def extensionUnloaded(self):
        self.stop_interceptor()

    def init_ui(self):
        self.main_panel = JPanel(BorderLayout())
        self.tab_container = JTabbedPane()
        
        # Panel 1: Controls
        tab_control = JPanel(BorderLayout())
        config_panel = JPanel(GridBagLayout())
        config_panel.setBorder(BorderFactory.createTitledBorder("Universal Pipeline Routing Settings"))
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.fill = GridBagConstraints.HORIZONTAL
        
        gbc.gridx = 0; gbc.gridy = 0; config_panel.add(JLabel("Local Listen Port:"), gbc)
        self.txt_local_port = JTextField("9101", 15)
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
        
        self.btn_action = JButton("Start Interceptor Listener", actionPerformed=self.btn_action_clicked)
        gbc.gridx = 1; gbc.gridy = 4; gbc.gridwidth = 2; config_panel.add(self.btn_action, gbc)
        
        self.txt_logs = JTextArea(18, 70)
        self.txt_logs.setEditable(False)
        scroll_logs = JScrollPane(self.txt_logs)
        scroll_logs.setBorder(BorderFactory.createTitledBorder("System Engine Status Logs"))
        
        tab_control.add(config_panel, BorderLayout.NORTH)
        tab_control.add(scroll_logs, BorderLayout.CENTER)
        
        # Panel 2: Live Packets
        tab_inspector = JPanel(BorderLayout())
        self.table_model = DefaultTableModel(["ID", "Network Context Route", "Size (Bytes)", "Summary Payload Preview"], 0)
        self.packet_table = JTable(self.table_model)
        self.packet_table.getSelectionModel().addListSelectionListener(TableSelectionHandler(self))
        scroll_table = JScrollPane(self.packet_table)
        
        self.txt_packet_details = JTextArea()
        self.txt_packet_details.setEditable(False)
        scroll_details = JScrollPane(self.txt_packet_details)
        
        split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT, scroll_table, scroll_details)
        split_pane.setDividerLocation(200)
        
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
            
        dump_view = self.generate_hex_dump(raw_bytes)
        detailed_breakdown = (
            "============================================================\n"
            " TRANSACTION PAYLOAD INSPECTION VISUALIZER                  \n"
            "============================================================\n"
            "Packet Ledger ID:  {}\n"
            "Event Timestamp:   {}\n"
            "Routing Context:   {}\n"
            "Payload Size:      {} Bytes\n\n"
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

    def btn_browse_clicked(self, event):
        chooser = JFileChooser()
        if chooser.showOpenDialog(self.main_panel) == JFileChooser.APPROVE_OPTION:
            self.txt_keystore_path.setText(chooser.getSelectedFile().getAbsolutePath())

    def btn_clear_table_clicked(self, event):
        self.table_model.setRowCount(0)
        self.packet_counter = 0
        with self.data_lock: del self.packet_payloads[:]
        self.txt_packet_details.setText("")

    def btn_action_clicked(self, event):
        if self.is_running: self.stop_interceptor()
        else: self.start_interceptor()

    def start_interceptor(self):
        try:
            self.local_port = int(self.txt_local_port.getText().strip())
            self.target_host = self.txt_target_host.getText().strip()
            self.keystore_path = self.txt_keystore_path.getText().strip()
            self.keystore_password = self.txt_keystore_password.getText()
        except Exception:
            self.ui_log("[-] Input Exception: Check configurations.")
            return

        try:
            ks = KeyStore.getInstance("PKCS12")
            ks.load(FileInputStream(self.keystore_path), list(self.keystore_password))
            kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
            kmf.init(ks, list(self.keystore_password))
            self.ssl_context = SSLContext.getInstance("TLS")
            self.ssl_context.init(kmf.getKeyManagers(), [TrustAllManager()], None)
        except Exception, e:
            self.ui_log("[-] Cryptographic Setup Failure: {}".format(str(e)))
            return

        try:
            self.server_socket = ServerSocket()
            self.server_socket.setReuseAddress(True)
            self.server_socket.bind(InetSocketAddress('127.0.0.1', self.local_port))
            self.is_running = True
            self.btn_action.setText("STOP Interceptor Listener")
            
            t = threading.Thread(target=self.listen_loop)
            t.daemon = True
            t.start()
            self.ui_log("[+] Active listener bound to local port {}.".format(self.local_port))
        except Exception, e:
            self.ui_log("[-] Bind Failure: {}".format(str(e)))

    def listen_loop(self):
        while self.is_running:
            try:
                client_sock = self.server_socket.accept()
                with self.connections_lock: self.active_connections.append(client_sock)
                t = threading.Thread(target=self.handle_client, args=(client_sock,))
                t.daemon = True
                t.start()
            except Exception: break

    def stop_interceptor(self):
        self.is_running = False
        try: self.server_socket.close()
        except: pass
        with self.connections_lock:
            for sock in self.active_connections:
                try: sock.close()
                except: pass
            del self.active_connections[:]
        self.btn_action.setText("Start Interceptor Listener")
        self.ui_log("[+] Listener stopped.")

    def handle_client(self, client_sock):
        server_sock = None
        try:
            server_sock = Socket()
            with self.connections_lock: self.active_connections.append(server_sock)
            server_sock.connect(InetSocketAddress(self.target_host, self.local_port), 5000)
            
            client_in = client_sock.getInputStream()
            client_out = client_sock.getOutputStream()
            server_in = server_sock.getInputStream()
            server_out = server_sock.getOutputStream()
            
            # Step 1: Read the 7-byte plain-text string from the client
            c2s_init = jarray.zeros(7, 'b')
            c2s_read = 0
            while c2s_read < 7:
                res = client_in.read(c2s_init, c2s_read, 7 - c2s_read)
                if res == -1: raise Exception("Client connection dropped prematurely")
                c2s_read += res
            
            self.ui_log_packet("HANDSHAKE (CLIENT -> SERVER)", 7, c2s_init)
            
            # Step 2: Forward the 7 bytes directly to the real server
            server_out.write(c2s_init, 0, 7)
            server_out.flush()
            
            # FIXED: Do NOT pause to read from the server here.
            # Proceed directly to launching concurrent TLS upgrades.
            self.ui_log("[*] Handshake forwarded. Instantly initializing parallel TLS layers...")
            
            ssl_client = self.ssl_context.getSocketFactory().createSocket(client_sock, None, True)
            ssl_client.setUseClientMode(False)
            ssl_server = self.ssl_context.getSocketFactory().createSocket(server_sock, None, True)
            ssl_server.setUseClientMode(True)
            
            t_client = threading.Thread(target=ssl_client.startHandshake)
            t_server = threading.Thread(target=ssl_server.startHandshake)
            t_client.start()
            t_server.start()
            
            t_client.join(timeout=5)
            t_server.join(timeout=5)
            self.ui_log("[+] TLS session handshakes successfully established.")
            
            # Step 3: Spin active duplex cleartext transmission tunnels
            t1 = threading.Thread(target=self.stream_pipe, args=(ssl_client, ssl_server, True, client_sock, server_sock))
            t2 = threading.Thread(target=self.stream_pipe, args=(ssl_server, ssl_client, False, client_sock, server_sock))
            t1.start()
            t2.start()
            
        except Exception, e:
            self.ui_log("[-] Session aborted mid-stream: {}".format(str(e)))
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
                
                dst.getOutputStream().write(data_bytes)
                dst.getOutputStream().flush()
                
                self.ui_log_packet(direction, len(data_bytes), data_bytes)
                self.log_to_burp(data_bytes if is_c2s else None, data_bytes if not is_c2s else None, endpoint_lbl)
        except Exception: pass
        finally: self.cleanup_sockets(raw_client, raw_server)

    def cleanup_sockets(self, s1, s2):
        try: s1.close()
        except: pass
        try: s2.close()
        except: pass

    def log_to_burp(self, request_bytes, response_bytes, endpoint):
        req_body = request_bytes if request_bytes else b""
        res_body = response_bytes if response_bytes else b""
        http_req = ("POST /{} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n").format(endpoint, self.FAKE_HOST, len(req_body)) + req_body
        http_res = ("HTTP/1.1 200 OK\r\nServer: Murex-RMI-Bridge\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n").format(len(res_body)) + res_body
        service = CustomHttpService(self.FAKE_HOST, 80, "http")
        self._callbacks.addToHistory(CustomHttpRequestResponse(http_req, http_res, service))

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        pass
