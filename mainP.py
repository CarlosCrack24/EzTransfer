from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.lang import Builder
from kivy.animation import Animation
from kivy.core.window import Window
from kivy.clock import Clock
from kivy.properties import StringProperty
from kivy.uix.popup import Popup
from kivy.uix.label import Label
from kivy.uix.filechooser import FileChooserListView
from kivy.uix.button import Button
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.textinput import TextInput
from tkinter import filedialog
import os
import sys
import socket
import threading
import tkinter as tk
import struct
import time

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS  
    except:
        base_path = os.path.abspath(".")  
    return os.path.join(base_path, relative_path)
file_path = resource_path("EstiloP.kv")
file_path1= resource_path("AestheticMomentItalicPersonalUsed.ttf")
file_path2= resource_path("GorideSansInked.otf")
file_path3= resource_path("enviar1.png")
file_path4= resource_path("recibir1.png")
# Cargar el archivo .kv desde la ruta absoluta

def obtener_ip_local():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80)) 
        ip_local = s.getsockname()[0]
        s.close()
        return ip_local
    except Exception as e:
        print("Error al obtener la IP local:", e)
        return "127.0.0.1"
PUERTO_DISCOVERY = 5002  # UDP
PUERTO_ENVIO = 5003       # TCP

def recibir_exactamente(conn, num_bytes):
    datos = b''
    while len(datos) < num_bytes:
        parte = conn.recv(num_bytes - len(datos))
        if not parte:
            raise ConnectionError("Conexión cerrada inesperadamente")
        datos += parte
    return datos

class MiVentana(BoxLayout):

    def seleccionar_directorio_con_tkinter(self, callback):
        def pedir_directorio():
            root = tk.Tk()
            root.withdraw()  
            carpeta = filedialog.askdirectory(title="Selecciona carpeta para guardar el archivo")
            root.destroy()
            if carpeta:
                callback(carpeta)

        threading.Thread(target=pedir_directorio).start()

    def mostrar_seleccionador_archivo(self):
        def buscar_dispositivos():
            dispositivos = self.buscar_receptores()  
            if dispositivos:
                Clock.schedule_once(lambda dt: self.mostrar_selector_ip(dispositivos))
            else:
                Clock.schedule_once(lambda dt: Popup(
                    title="Sin dispositivos",
                    content=Label(text="No se encontraron dispositivos disponibles."),
                    size_hint=(0.8, 0.4)
                ).open())

        threading.Thread(target=buscar_dispositivos, daemon=True).start()

    def mostrar_selector_ip(self, lista_ips):
        box = BoxLayout(orientation='vertical', spacing=10, padding=10)
        box.add_widget(Label(text="Selecciona el dispositivo al que deseas enviar:"))

        for ip in lista_ips:
            btn = Button(text=f"Enviar a {ip}", size_hint_y=None, height=40)

            def abrir_archivo_y_enviar(instancia_btn, ip_destino=ip):
                def seleccionar_y_enviar():
                    root = tk.Tk()
                    root.withdraw()
                    ruta = filedialog.askopenfilenames(title="Selecciona uno o más archivos para enviar")
                    if ruta:
                        self.enviar_archivos(ip_destino, ruta)
                    root.destroy()
                    if ruta:
                        Clock.schedule_once(lambda dt: Popup(
                            title="Archivo enviado",
                            content=Label(text=f"Archivo enviado a: {ip_destino}"),
                            size_hint=(0.8, 0.4)
                        ).open())
                threading.Thread(target=seleccionar_y_enviar, daemon=True).start()
            btn.bind(on_release=abrir_archivo_y_enviar)
            box.add_widget(btn)

        popup = Popup(title="Equipos disponibles", content=box, size_hint=(0.8, 0.8))
        popup.open()

    def iniciar_servidor(self):
        def responder_broadcast():
            print("Servidor de descubrimiento UDP listo y esperando broadcasts...")
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('', PUERTO_DISCOVERY))
            while True:
                data, addr = s.recvfrom(1024)
                if data == b"DISCOVER_RECEIVER":
                    print(f"Respuesta a broadcast enviada a {addr[0]}")
                    s.sendto(b"RECEIVER_HERE", addr)

        threading.Thread(target=responder_broadcast, daemon=True).start()
        threading.Thread(target=self.recibir_archivo, daemon=True).start()

    def recibir_archivo(self):
        host = obtener_ip_local()
        buffer_size = 4096

        server_socket = socket.socket()
        server_socket.bind((host, PUERTO_ENVIO))
        server_socket.listen(1)
        print(f"Esperando conexión en {host}:{PUERTO_ENVIO}...")

        self.directorio_destino = None

        def pedir_directorio():
            root = tk.Tk()
            root.withdraw()
            carpeta = filedialog.askdirectory(title="Selecciona carpeta para guardar los archivos")
            self.directorio_destino = carpeta
            root.destroy()

        pedir_directorio() 
        if not self.directorio_destino:
            print("No se seleccionó carpeta. Abortando servidor.")
            return
        def manejar_cliente(conn, addr):
            while self.directorio_destino is None:
                time.sleep(0.1)
                
            carpeta = self.directorio_destino
            try:
                cantidad_archivos_bytes = recibir_exactamente(conn, 4)
                cantidad_archivos = struct.unpack('!I', cantidad_archivos_bytes)[0]
                print(f"Conectado desde: {addr}, cantidad de archivos: {cantidad_archivos}")

                for _ in range(cantidad_archivos):
                    # Recibir nombre del archivo
                    nombre_len_bytes = recibir_exactamente(conn, 4)
                    nombre_len = struct.unpack('!I', nombre_len_bytes)[0]
                    nombre_bytes = recibir_exactamente(conn, nombre_len)
                    filename = nombre_bytes.decode('utf-8', errors="replace")

                    # Recibir tamaño y contenido
                    tamano_bytes = recibir_exactamente(conn, 8)
                    tamano_archivo = struct.unpack('!Q', tamano_bytes)[0]

                    ruta_destino = os.path.join(carpeta, f"recibido_{filename}")
                    with open(ruta_destino, "wb") as f:
                        recibido = 0
                        while recibido < tamano_archivo:
                            chunk_size = min(4096, tamano_archivo - recibido)
                            parte = conn.recv(chunk_size)
                            if not parte:
                                raise ConnectionError("Conexión cerrada inesperadamente durante la transferencia")
                            f.write(parte)
                            recibido += len(parte)

                    print(f"Archivo guardado en: {ruta_destino}")

                conn.close()
                # Mostrar popup al finalizar
                Clock.schedule_once(lambda dt: Popup(
                    title="Archivos recibidos",
                    content=Label(text="Todos los archivos se han recibido correctamente."),
                    size_hint=(0.8, 0.4)
                ).open())

            except Exception as e:
                print("Error al recibir archivo:", e)
                import traceback
                traceback.print_exc()
                conn.close()

        def esperar_conexion():
            while True:
                conn, addr = server_socket.accept()
                print(f"Conexión TCP aceptada desde {addr}")
                threading.Thread(target=manejar_cliente, args=(conn, addr), daemon=True).start()

        threading.Thread(target=esperar_conexion, daemon=True).start()

    def enviar_archivos(self, ip_destino, rutas_archivos):
        def enviar():
            buffer_size = 4096
            s = socket.socket()
            s.connect((ip_destino, PUERTO_ENVIO))
            print(f"Conectado a {ip_destino}:{PUERTO_ENVIO}, enviando archivos...")
            # Enviar cantidad de archivos
            s.send(struct.pack('!I', len(rutas_archivos)))

            for ruta_archivo in rutas_archivos:
                filename = os.path.basename(ruta_archivo)
                nombre_bytes = filename.encode()
                s.send(struct.pack('!I', len(nombre_bytes)))
                s.send(nombre_bytes)

                file_size = os.path.getsize(ruta_archivo)
                s.send(struct.pack('!Q', file_size))

                with open(ruta_archivo, "rb") as f:
                    while True:
                        bytes_read = f.read(buffer_size)
                        if not bytes_read:
                            break
                        s.sendall(bytes_read)
                time.sleep(0.5)
            time.sleep(5)
            s.close()
            print("Archivos enviados correctamente.")

        threading.Thread(target=enviar, daemon=True).start()
        print("Transferencia completa. Socket cerrado.")
    def buscar_receptores(self, puerto_broadcast=5002, timeout=7):
        dispositivos = set()
        try:
            print("Iniciando búsqueda de receptores...")
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.settimeout(timeout)
            mensaje = b"DISCOVER_RECEIVER"
            s.sendto(mensaje, ('<broadcast>', puerto_broadcast))
            print("Mensaje de broadcast enviado, esperando respuestas...")

            tiempo_inicio = socket.getdefaulttimeout()
            fin = timeout
            while True:
                try:
                    datos, addr = s.recvfrom(1024)
                    print(f"Respuesta UDP desde: {addr[0]} con datos: {datos}")
                    if datos == b"RECEIVER_HERE":
                        print(f"Receptor encontrado en: {addr[0]}")
                        dispositivos.add(addr[0])
                except socket.timeout:
                    print("Tiempo de espera agotado sin más respuestas.")
                    break  
        except Exception as e:
            print("Error durante la búsqueda de receptores:", e)
            
        return list(dispositivos)
    

    font1= StringProperty(resource_path("AestheticMomentItalicPersonalUsed.ttf"))
    font2= StringProperty(resource_path("GorideSansInked.otf"))
    enviar1= StringProperty(resource_path("enviar1.png"))
    recibir1= StringProperty(resource_path("recibir1.png"))
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.bind(size=self.actualizar_circulos)
        self._tamano_original = {}
        self._pos_original = {}
        Clock.schedule_interval(self.verificar_hover, 0.1)
    
    def verificar_hover(self, dt):
        mouse_pos = Window.mouse_pos
        hovering = False

        for id_name in ['left_circle', 'right_circle']:
            widget = self.ids.get(id_name)
            if widget:
                local_pos = widget.to_widget(*mouse_pos)
                if widget.collide_point(*local_pos):
                    hovering = True
                    break  
        Window.set_system_cursor('hand' if hovering else 'arrow')
    def actualizar_circulos(self, *args):
        min_size = 150
        try:
            base_width = self.width * 0.5 * 0.6
            base_height = self.height * 0.65 * 0.6
            size = max(min(base_width, base_height), min_size)

            for id_name in ['left_circle', 'right_circle']:
                circle = self.ids.get(id_name)
                if circle:
                    circle.size = (size, size)

                # Guardamos tamaño y posición actual como originales
                    self._tamano_original[id_name] = tuple(circle.size)
                    self._pos_original[id_name] = tuple(circle.pos)
        except KeyError:
            pass


    def encoger_boton(self, id_widget):
        widget = self.ids.get(id_widget)
        if widget:
            if id_widget not in self._tamano_original:
                self._tamano_original[id_widget] = tuple(widget.size)
                self._pos_original[id_widget] = tuple(widget.pos)

            nuevo_tamano = (widget.size[0] * 0.9, widget.size[1] * 0.9)
            nueva_pos = (
                widget.pos[0] + (widget.size[0] - nuevo_tamano[0]) / 2,
                widget.pos[1] + (widget.size[1] - nuevo_tamano[1]) / 2
            )
            Animation(size=nuevo_tamano, pos=nueva_pos, duration=0.05).start(widget)

    def restaurar_boton(self, id_widget, funcion_post_animacion=None):
        widget = self.ids.get(id_widget)
        if widget and id_widget in self._tamano_original:
            original_size = self._tamano_original[id_widget]
            original_pos = self._pos_original[id_widget]
            anim = Animation(size=original_size, pos=original_pos, duration=0.05)

            if funcion_post_animacion:
                anim.bind(on_complete=lambda *args: funcion_post_animacion())

            anim.start(widget)

    def funcion_boton_izquierdo(self):
        print("Botón izquierda pulsado")
        print("Esperando archivo...")
        ip = obtener_ip_local()
        self.iniciar_servidor()
        Popup(title="IP del receptor", content=Label(text=f"Tu IP es: {ip}"), size_hint=(0.6, 0.3)).open()


    def funcion_boton_derecho(self):
        print("Botón derecho pulsado")
        self.mostrar_seleccionador_archivo()


class MiApp(App):
    def build(self):
        Builder.load_file(file_path)
        return MiVentana()


if __name__ == '__main__':
    MiApp().run()