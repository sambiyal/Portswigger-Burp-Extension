# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener, IHttpRequestResponse, IHttpService
import socket
import threading
from javax.net.ssl import SSLContext, X509TrustManager, KeyManagerFactory
from java.io import FileInputStream, ByteArrayOutputStream
from java.security import KeyStore

# ==================== UNIVERSAL CONFIGURATION ====================
LOCAL_PORT = 9101
TARGET_HOST = "10.100.113.45"
TARGET_PORT = 9101
FAKE_HOST = "murex-rmi-bridge"

# Path to your Burp CA certificate KeyStore (.p12 format)
# Export this directly from Burp Suite Pro if needed (Default password is changeit)
KEYSTORE_PATH = r"C:\burp\burpca.p12"
KEYSTORE_PASSWORD = "changeit"
# =================================================================

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

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("murex_rmi_interception")
        callbacks.registerHttpListener(self)
        
        print "[*] Murex RMI StartTLS Interceptor Loaded Successfully."
        print "[*] Listening locally on port: {}".format(LOCAL_PORT)
        print "[*] Upstream target configured: {}:{}".format(TARGET_HOST, TARGET_PORT)
        
        # Initialize internal SSL Context using your provided Burp CA Bundle
        self.init_ssl()
        
        # Launch the asynchronous network listening socket thread
        threading.Thread(target=self.start_local_listener).start()

    def init_ssl(self):
        try:
            ks = KeyStore.getInstance("PKCS12")
            ks.load(FileInputStream(KEYSTORE_PATH), list(KEYSTORE_PASSWORD))
            kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
            kmf.init(ks, list(KEYSTORE_PASSWORD))
            
            self.ssl_context = SSLContext.getInstance("TLS")
            self.ssl_context.init(kmf.getKeyManagers(), [TrustAllManager()], None)
            print "[+] Cryptographic SSL Context built successfully."
        except Exception, e:
            print "[-] Critical Error initializing SSL KeyStore: {}".format(str(e))

    def start_local_listener(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('127.0.0.1', LOCAL_PORT))
        server.listen(15)
        
        while True:
            client_sock, addr = server.accept()
            threading.Thread(target=self.handle_client, args=(client_sock,)).start()

    def handle_client(self, client_sock):
        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.connect((TARGET_HOST, TARGET_PORT))
            
            # Phase 1: Catch and forward the plain-text 7-byte JRMI baseline header
            c2s_init = client_sock.recv(7)
            server_sock.sendall(c2s_init)
            
            s2c_init = server_sock.recv(7)
            client_sock.sendall(s2c_init)
            
            self.log_to_burp(c2s_init, s2c_init, "handshake_initialization")
            
            # Phase 2: Dynamic Sockets upgrade to SSL/TLS mid-stream (StartTLS)
            ssl_client = self.ssl_context.getSocketFactory().createSocket(client_sock, client_sock.getInetAddress().getHostAddress(), client_sock.getPort(), True)
            ssl_client.setUseClientMode(False)
            ssl_client.startHandshake()
            
            ssl_server = self.ssl_context.getSocketFactory().createSocket(server_sock, TARGET_HOST, TARGET_PORT, True)
            ssl_server.setUseClientMode(True)
            ssl_server.startHandshake()
            
            # Phase 3: Spin up active streaming duplex tunnel loops
            t1 = threading.Thread(target=self.stream_pipe, args=(ssl_client, ssl_server, True))
            t2 = threading.Thread(target=self.stream_pipe, args=(ssl_server, ssl_client, False))
            t1.start()
            t2.start()
            
        except Exception, e:
            print "[-] Session handshake boundary alignment dropped: {}".format(str(e))

    def stream_pipe(self, src, dst, is_c2s):
        buffer_size = 4096
        try:
            while True:
                data = src.getInputStream().read(buffer_size)
                if data == -1 or data == 0:
                    break
                
                # Convert the Java byte stream securely into standard string payloads
                out = ByteArrayOutputStream()
                out.write(data, 0, len(data))
                data_bytes = out.toByteArray()
                
                # Forward raw traffic immediately to target destination to minimize latency
                dst.getOutputStream().write(data_bytes)
                dst.getOutputStream().flush()
                
                # Render the payloads directly into Burp's Core HTTP Proxy space
                if is_c2s:
                    self.log_to_burp(data_bytes, None, "rmi_data_c2s")
                else:
                    self.log_to_burp(None, data_bytes, "rmi_data_s2c")
        except Exception:
            pass
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
        ).format(endpoint, FAKE_HOST, len(req_body)) + req_body
        
        http_res = (
            "HTTP/1.1 200 OK\r\n"
            "Server: Murex-RMI-Bridge\r\n"
            "Content-Type: application/octet-stream\r\n"
            "Content-Length: {}\r\n\r\n"
        ).format(len(res_body)) + res_body
        
        service = CustomHttpService(FAKE_HOST, 80, "http")
        item = CustomHttpRequestResponse(http_req, http_res, service)
        self._callbacks.addToHistory(item)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Only catch replay loops targeted against our virtual wrapper host
        if messageInfo.getHttpService().getHost() != FAKE_HOST:
            return
            
        if messageIsRequest:
            try:
                request_info = self._helpers.analyzeRequest(messageInfo)
                req_bytes = messageInfo.getRequest()
                body_offset = request_info.getBodyOffset()
                rmi_payload = req_bytes[body_offset:]
                
                # Spin up an independent out-of-band RMI TLS channel for the Repeater replay action
                backend_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                backend_sock.connect((TARGET_HOST, TARGET_PORT))
                
                backend_sock.sendall(b"JRMI\x00\x01\x01")
                backend_sock.recv(7)
                
                ssl_backend = self.ssl_context.getSocketFactory().createSocket(backend_sock, TARGET_HOST, TARGET_PORT, True)
                ssl_backend.setUseClientMode(True)
                ssl_backend.startHandshake()
                
                ssl_backend.getOutputStream().write(rmi_payload)
                ssl_backend.getOutputStream().flush()
                
                backend_sock.setSoTimeout(2000)
                input_stream = ssl_backend.getInputStream()
                
                res_out = ByteArrayOutputStream()
                buffer_size = 4096
                while True:
                    try:
                        chunk = input_stream.read()
                        if chunk == -1: break
                        res_out.write(chunk)
                        if input_stream.available() == 0: break
                    except Exception:
                        break
                        
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
                http_err = (
                    "HTTP/1.1 500 Internal Server Error\r\n"
                    "Content-Type: text/plain\r\n"
                    "Content-Length: {}\r\n\r\n"
                ).format(len(err_msg)) + err_msg
                messageInfo.setResponse(http_err)