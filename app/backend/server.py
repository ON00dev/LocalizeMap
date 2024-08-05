import http.server
import ssl

def run_server():
    server_address = ('localhost', 4443)
    httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)

    # Caminhos para o certificado e chave privada
    cert_file = './LocalizeMap/app/data/data/certificate.pem'
    key_file = './LocalizeMap/app/data/data/key1.pem'

    httpd.socket = ssl.wrap_socket(httpd.socket, certfile=cert_file, keyfile=key_file, server_side=True)
    print(f"Servindo em https://{server_address[0]}:{server_address[1]}")
    httpd.serve_forever()


if __name__ == "__main__":
    run_server()
