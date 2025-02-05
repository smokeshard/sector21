import datetime
import http.client
import re
import socket
import ssl

class DomainScanner:
    def log(self, message):
        with open(self.scanResult, "a") as log:
            log.write(message + "\n")
        print(message)

    def __init__ (self, domain):
        self.domain = domain
        self.scanResult = f"Scan Results for {domain}.txt"
        self.log(f"Scan for '{domain}' Started at {datetime.datetime.now()}\n\n=====")

    def portScanning(self):
        self.log("\n[+] Performing Port Scan...\n")
        ports = [
            1000, 10000, 10001, 1001, 10011, 10101, 1080, 1099, 110, 11011, 1111, 11211, 119, 1194, 123, 123, 1234,
            12345, 12543, 12931, 1337, 143, 1433, 1434, 15000, 1521, 1555, 161, 162, 177, 18000, 194, 20, 2000, 20000,
            20002, 2005, 2020, 2048, 20480, 20481, 20490, 21, 2101, 2121, 21345, 22, 2222, 23, 2323, 2345, 25, 25000,
            2545, 2546, 27017, 27018, 28017, 3000, 30000, 303, 3030, 30303, 30304, 3060, 3128, 31337, 3306, 33333, 3389,
            3434, 34343, 3600, 3690, 4000, 40000, 4011, 4020, 4040, 4200, 4242, 4321, 443, 4433, 4443, 4444, 44444, 445,
            45000, 45010, 4554, 4848, 500, 5000, 5050, 50500, 50505, 5060, 5101, 5150, 520, 53, 5335, 5353, 5432, 54321,
            5522, 5555, 55555, 5632, 5858, 587, 5900, 5985, 5986, 6000, 60000, 631, 6379, 65430, 65431, 65432, 6660,
            6661, 6662, 6663, 6664, 6665, 6666, 6667, 6668, 6669, 6670, 6680, 6697, 6699, 67, 6789, 68, 69, 7000, 7070,
            7171, 7777, 7778, 7800, 80, 8000, 8080, 8088, 8443, 8888, 9000, 9001, 9035, 9080, 9090, 9876, 993, 995, 999,
            9999,
            ]
        for port in ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)
                result = sock.connect_ex((self.domain, port))
                if result == 0:
                    self.log(f"  - Port {port} is OPEN")
                else:
                    print(f"  - Port {port} is CLOSED")

    def checkSSL(self):
        self.log("\n[+] Checking SSL Certificate...\n")
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=self.domain) as sock:
                sock.connect((self.domain, 443))
                cert = sock.getpeercert()
                expiry = cert['notAfter']
                self.log(f"  - SSL Certificate Valid Until: {expiry}")
        except Exception as e:
            self.log(f"  - SSL Check Failed: {e}")
    
    def checkHTTPHeaders(self):
        self.log("\n[+] Checking HTTP Headers...\n")
        try:
            connection = http.client.HTTPSConnection(self.domain)
            connection.request("GET", "/")
            response = connection.getresponse()
            headers = response.getheaders()
            connection.close()
            for header, value in headers:
                self.log(f"  - {header}: {value}")
        except Exception as e:
            self.log(f"  - HTTP Headers Check Failed: {e}")
    
    def checkXSS(self):
        self.log("\n[+] Checking for Cross-site Scripting...\n")
        payload = "<script>alert('XSS')</script>"
        try:
            connection = http.client.HTTPConnection(self.domain)
            connection.request("GET", f"/?q={payload}")
            response = connection.getresponse().read().decode(errors="ignore")
            connection.close()
            if payload in response:
                self.log("  - Potential XSS Vulnerability Found!")
            else:
                self.log("  - No XSS Vulnerability Detected.")
        except Exception as e:
            self.log(f"  - XSS Test Failed: {e}")

    def runScan(self):
        self.portScanning()
        self.checkSSL()
        self.checkHTTPHeaders()
        self.checkXSS()
        self.log(f"\n=====\n\nScanning Completed at {datetime.datetime.now()}")

if __name__ == "__main__":
    domain = input("Enter Domain to Scan: ")
    scanner = DomainScanner(domain)
    scanner.runScan()