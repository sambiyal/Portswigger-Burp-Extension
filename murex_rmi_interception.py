# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener, IHttpRequestResponse, IHttpService, ITab, IExtensionStateListener
import threading
import sys
import jarray
import datetime
import java.awt
from java.net import ServerSocket, Socket, InetSocketAddress
from java.io import ByteArrayOutputStream
from java.lang import String as JString
from javax.swing import JPanel, JLabel, JTextField, JButton, JTextArea, JScrollPane, BorderFactory, SwingUtilities, JTabbedPane, JTable, JSplitPane
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
    def getComment(self): return "Raw TCP Packet Stream"
    def setComment(self, comment): pass
    def getHighlight(self): return "gray"
    def setHighlight(self, highlight): pass

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
        self.server_socket = None
        self.active_connections = []
        self.connections_lock = threading.Lock()
        
        self.packet_payloads = []
        self.data_lock = threading.Lock()
        self.packet_counter = 0
        self.FAKE_HOST = "murex-raw-bridge"
        
        self.init_ui()
        callbacks.addSuiteTab(self)
        self.ui_log("[*] Debug Baseline Pipe Loaded. SSL/TLS Decryption is completely disabled.")

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
        config_panel.setBorder(BorderFactory.createTitledBorder("Raw TCP Pass-Through Routing Settings"))
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.fill = GridBagConstraints.HORIZONTAL
        
        gbc.gridx = 0; gbc.gridy = 0; config_panel.add(JLabel("Local Listen Port:"), gbc)
        self.txt_local_port = JTextField("9101", 15)
        gbc.gridx = 1; gbc.gridy = 0; config_panel.add(self.txt_local_port, gbc)
        
        gbc.gridx = 0; gbc.gridy = 1; config_panel.add(JLabel("Upstream Target Host/IP:"), gbc)
        self.txt_target_host = JTextField("10.100.113.45", 20)
        gbc.gridx = 1; gbc.gridy = 1; config_panel.add(self.txt_target_host, gbc)
        
        self.btn_action = JButton("Start Interceptor Listener", actionPerformed=self.btn_action_clicked)
        gbc.gridx = 1; gbc.gridy = 2; gbc.gridwidth = 2; config_panel.add(self.btn_action, gbc)
        
        self.txt_logs = JTextArea(18, 70)
        self.txt_logs.setEditable(False)
        scroll_logs = JScrollPane(self.txt_logs)
        scroll_logs.setBorder(BorderFactory.createTitledBorder("System Engine Status Logs"))
        
        tab_control.add(config_panel, BorderLayout.NORTH)
        tab_control.add(scroll_logs, BorderLayout.CENTER)
        
        # Panel 2: Live Packets
        tab_inspector = JPanel(BorderLayout())
        self.table_model = DefaultTableModel(["ID", "Network Context Route", "Size (Bytes)", "Raw Hex/ASCII Preview (Encrypted)"], 0)
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
        except Exception:
            preview_string = "[Raw Byte Buffer Block]"
            
        dump_view = self.generate_hex_dump(raw_bytes)
        detailed_breakdown = (
            "============================================================\n"
            " RAW TCP TRANSPARENT PASS-THROUGH VISUALIZER                \n"
            "============================================================\n"
            "Packet Ledger ID:  {}\n"
            "Event Timestamp:   {}\n"
            "Routing Context:   {}\n"
            "Payload Size:      {} Bytes\n\n"
            "--------------- RAW STREAM BUFFER (ENCRYPTED) ---------------\n"
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
        except Exception:
            self.ui_log("[-] Input Exception: Check configurations.")
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
            self.ui_log("[+] Active blind pass-through pipe listening on port {}.".format(self.local_port))
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
        self.ui_log("[+] Baseline pipe stopped.")

    def handle_client(self, client_sock):
        server_sock = None
        try:
            # Open direct upstream connection to the server on the exact same port context
            server_sock = Socket()
            with self.connections_lock: self.active_connections.append(server_sock)
            server_sock.connect(InetSocketAddress(self.target_host, self.local_port), 5000)
            self.ui_log("[+] Socket connected to server. Shuttling raw bytes...")
            
            client_in = client_sock.getInputStream()
            client_out = client_sock.getOutputStream()
            server_in = server_sock.getInputStream()
            server_out = server_sock.getOutputStream()
            
            # Spin raw, immediate duplex streaming tunnels without handling handshakes or data parsing
            t1 = threading.Thread(target=self.stream_pipe, args=(client_in, server_out, "CLIENT -> SERVER", client_sock, server_sock, True))
            t2 = threading.Thread(target=self.stream_pipe, args=(server_in, client_out, "SERVER -> CLIENT", client_sock, server_sock, False))
            t1.start()
            t2.start()
            
        except Exception, e:
            self.ui_log("[-] Connection mapping broken: {}".format(str(e)))
            self.cleanup_sockets(client_sock, server_sock)

    def stream_pipe(self, src_in, dst_out, direction, raw_client, raw_server, is_c2s):
        buf = jarray.zeros(4096, 'b')
        endpoint_lbl = "raw_c2s" if is_c2s else "raw_s2c"
        try:
            while self.is_running:
                bytes_read = src_in.read(buf)
                if bytes_read == -1 or not self.is_running: break
                if bytes_read == 0: continue
                
                # Forward raw byte array slice immediately without reading or modifying contents
                dst_out.write(buf, 0, bytes_read)
                dst_out.flush()
                
                # Extract copy for logging
                out = ByteArrayOutputStream()
                out.write(buf, 0, bytes_read)
                data_bytes = out.toByteArray()
                
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
        http_res = ("HTTP/1.1 200 OK\r\nServer: Murex-Raw-Bridge\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n").format(len(res_body)) + res_body
        service = CustomHttpService(self.FAKE_HOST, 80, "http")
        self._callbacks.addToHistory(CustomHttpRequestResponse(http_req, http_res, service))

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        pass
