from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.lang import Builder
from kivy.animation import Animation
from kivy.core.window import Window
from kivy.clock import Clock
import os
from kivy.properties import StringProperty
import sys
import socket
import threading
from kivy.uix.popup import Popup
from kivy.uix.label import Label
from kivy.uix.filechooser import FileChooserListView
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.uix.modalview import ModalView
import struct
import time
from android.storage import primary_external_storage_path
from android.permissions import request_permissions, Permission
request_permissions([
    Permission.READ_EXTERNAL_STORAGE,
    Permission.WRITE_EXTERNAL_STORAGE,
    Permission.ACCESS_FINE_LOCATION,
    Permission.ACCESS_COARSE_LOCATION,
    Permission.ACCESS_WIFI_STATE,
    Permission.CHANGE_WIFI_MULTICAST_STATE,
])
from jnius import autoclass, cast
from android import activity
from android import mActivity

Intent = autoclass("android.content.Intent")
Settings = autoclass("android.provider.Settings")
Uri = autoclass("android.net.Uri")

def solicitar_acceso_total():
    intent = Intent()
    intent.setAction(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION)
    uri = Uri.fromParts("package", mActivity.getPackageName(), None)
    intent.setData(uri)
    mActivity.startActivity(intent)

def adquirir_multicast_lock():
    PythonActivity = autoclass('org.kivy.android.PythonActivity')
    Context = autoclass('android.content.Context')
    activity = PythonActivity.mActivity
    wifi_service = activity.getSystemService(Context.WIFI_SERVICE)
    WifiManager = autoclass('android.net.wifi.WifiManager')
    multicast_lock = wifi_service.createMulticastLock("mi_lock_udp")
    multicast_lock.setReferenceCounted(True)
    multicast_lock.acquire()

def on_activity_result(request_code, result_code, intent):
    if request_code == 42 and result_code == -1:
        ClipData = autoclass('android.content.ClipData')
        uris = []

        if intent.getData():
            uris.append(intent.getData())
        elif intent.getClipData():
            clip_data = intent.getClipData()
            for i in range(clip_data.getItemCount()):
                uris.append(clip_data.getItemAt(i).getUri())

        rutas = []
        for uri in uris:
            rutas.append(uri.toString()) 
        App.get_running_app().root.enviar_archivos(App.get_running_app().root._ip_destino_actual, rutas)
def abrir_selector_archivos(callback):
    PythonActivity = autoclass('org.kivy.android.PythonActivity')
    Intent = autoclass('android.content.Intent')
    activity.bind(on_activity_result=callback)

    intent = Intent(Intent.ACTION_GET_CONTENT)
    intent.setType("*/*")
    intent.addCategory(Intent.CATEGORY_OPENABLE)
    intent.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, True)  # Para permitir múltiples archivos
    PythonActivity.mActivity.startActivityForResult(intent, 42)


ruta_base = primary_external_storage_path()

# Window.size = (360, 640)  
Window.fullscreen = 'auto'  

from android import activity
from jnius import autoclass

def pedir_directorio_para_guardar(callback):
    chooser = ModalView(size_hint=(0.9, 0.9))
    box = BoxLayout(orientation='vertical', spacing=10, padding=10)
    filechooser = FileChooserListView(path=primary_external_storage_path(), filters=['!*.'], dirselect=True)
    btn = Button(text="Usar esta carpeta", size_hint_y=None, height=200)

    def seleccionar(_):
        if filechooser.path:
            callback(filechooser.path)
            chooser.dismiss()

    btn.bind(on_release=seleccionar)
    box.add_widget(filechooser)
    box.add_widget(btn)
    chooser.add_widget(box)
    chooser.open()

def obtener_ip_local():
    import netifaces
    interfaces = netifaces.interfaces()
    for i in interfaces:
        ifaddresses = netifaces.ifaddresses(i)
        inet = ifaddresses.get(netifaces.AF_INET)
        if inet:
            for link in inet:
                ip = link['addr']
                if not ip.startswith("127."):
                    return ip
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

def seleccionar_archivo(callback):
    chooser = ModalView(size_hint=(0.9, 0.9))
    box = BoxLayout(orientation='vertical')
    filechooser = FileChooserListView()
    btn = Button(text="Seleccionar")

    def seleccionar(_):
        if filechooser.selection:
            callback(filechooser.selection)
            chooser.dismiss()

    btn.bind(on_release=seleccionar)
    box.add_widget(filechooser)
    box.add_widget(btn)
    chooser.add_widget(box)
    chooser.open()

class MiVentana(BoxLayout):

    
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
            btn = Button(text=f"Enviar a {ip}", size_hint_y=None, height=200)

            def make_callback(ip_destino):
                def iniciar_seleccion(_):
                    self._ip_destino_actual = ip_destino  # Guardamos la IP para usarla después
                    abrir_selector_archivos(on_activity_result)
                return iniciar_seleccion
            btn.bind(on_release=make_callback(ip))
            box.add_widget(btn)
        popup = Popup(title="Equipos disponibles", content=box, size_hint=(0.8, 0.8))
        popup.open()

    def iniciar_servidor(self):
        adquirir_multicast_lock()
        def responder_broadcast():
            print("Receptor escuchando broadcasts...")
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('', PUERTO_DISCOVERY))
            while True:
                data, addr = s.recvfrom(1024)
                print(f"Broadcast recibido: {data} de {addr}")
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

                    # Si es un APK, crear una subcarpeta "ApksRecibidas"
                    if filename.lower().endswith(".apk"):
                        carpeta_apk = os.path.join(carpeta, "ApksRecibidas")
                        if not os.path.exists(carpeta_apk):
                            os.makedirs(carpeta_apk)
                        ruta_destino = os.path.join(carpeta_apk, f"recibido_{filename}")
                    else:
                        ruta_destino = os.path.join(carpeta, f"recibido_{filename}")
                    try:
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
                    except Exception as e:
                        print(f"Error al guardar el archivo {filename}: {e}")

                conn.close()

                # Mostrar popup al finalizar
                Clock.schedule_once(lambda dt: Popup(
                    title="Archivos recibidos",
                    content=Label(text="Todos los archivos se han recibido correctamente."),
                    size_hint=(0.8, 0.4)
                ).open())

            except Exception as e:
                print("Error al recibir archivo:", e)
                conn.close()


        def esperar_conexion():
            while True:
                conn, addr = server_socket.accept()
                threading.Thread(target=manejar_cliente, args=(conn, addr), daemon=True).start()

        threading.Thread(target=esperar_conexion, daemon=True).start()

    def enviar_archivos(self, ip_destino, uris):
        def enviar():
            buffer_size = 4096
            s = socket.socket()
            try:
                s.connect((ip_destino, PUERTO_ENVIO))
            except Exception as e:
                print("Error al conectar:", e)
                Clock.schedule_once(lambda dt: Popup(
                    title="Error",
                    content=Label(text="No se pudo conectar al receptor"),
                    size_hint=(0.8, 0.4)
                ).open())
                return

            s.send(struct.pack('!I', len(uris)))  # Número de archivos

            PythonActivity = autoclass('org.kivy.android.PythonActivity')
            context = PythonActivity.mActivity
            ContentResolver = context.getContentResolver()
            Uri = autoclass('android.net.Uri')
            BufferedInputStream = autoclass('java.io.BufferedInputStream')

            for uri_str in uris:
                try:
                    uri = Uri.parse(uri_str)
                    cursor = ContentResolver.query(uri, None, None, None, None)
                    filename = "archivo_android"
                    if cursor and cursor.moveToFirst():
                        name_index = cursor.getColumnIndex("_display_name")
                        if name_index != -1:
                            filename = cursor.getString(name_index)
                    cursor.close()


                    stream = ContentResolver.openInputStream(uri)
                    bis = BufferedInputStream(stream)

                    # Lee el archivo en bloques y cuenta su tamaño real
                    chunks = []
                    total_size = 0
                    while True:
                        buffer = bytearray(4096)
                        length = bis.read(buffer)
                        if length == -1 or length == 0:
                            break
                        data = bytes(buffer[:length])
                        chunks.append(data)
                        total_size += len(data)
                    if total_size == 0:
                        print(f"Archivo vacío o error de lectura: {filename}")
                        continue  # Saltar este archivo y pasar al siguiente
                    print(f"Enviando archivo: {filename}")
                    print(f"Tamaño calculado: {total_size}")
                    print(f"Número de bloques: {len(chunks)}")

                    nombre_bytes = filename.encode('utf-8')
                    s.send(struct.pack('!I', len(nombre_bytes)))
                    s.send(nombre_bytes)
                    s.send(struct.pack('!Q', total_size))

                    # Enviar contenido
                    for chunk in chunks:
                        s.sendall(chunk)

                    bis.close()
                    stream.close()
                    time.sleep(0.5)

                except Exception as e:
                    print(f"Error al enviar archivo {uri_str}: {e}")
                    import traceback
                    traceback.print_exc()

            s.close()
            print("Archivos enviados correctamente.")

        threading.Thread(target=enviar, daemon=True).start()

    def buscar_receptores(self, puerto_broadcast=5002, timeout=4):
        adquirir_multicast_lock()
        dispositivos = set()
        intentos = 3 
        for _ in range(intentos):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                s.settimeout(timeout)
                mensaje = b"DISCOVER_RECEIVER"
                s.sendto(mensaje, ('<broadcast>', puerto_broadcast))
                print("Mensaje de broadcast enviado, esperando respuestas...")

                while True:
                    try:
                        datos, addr = s.recvfrom(1024)
                        if datos == b"RECEIVER_HERE":
                            print(f"Receptor encontrado en: {addr[0]}")
                            dispositivos.add(addr[0])
                            
                    except socket.timeout:
                        break  
            except Exception as e:
                print("Error durante la búsqueda de receptores:", e)

            if dispositivos:
                break 
            else:
                print("Reintentando descubrimiento...")
                time.sleep(1)
        return list(dispositivos)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.bind(size=self.actualizar_circulos)
        self._tamano_original = {}
        self._pos_original = {}

    def actualizar_circulos(self, *args):
        try:
            size = min(self.width, self.height) * 0.75 * 0.75
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
        self.directorio_destino = None
        def luego_de_elegir(path):
            # self.solicitar_acceso_total()
            print("Botón izquierda pulsado")
            print("Esperando archivo...")
            self.directorio_destino = path
            print(f"Guardando en carpeta: {self.directorio_destino}")
            self.iniciar_servidor()

            def mostrar_ip(_):
                ip = obtener_ip_local()
                Popup(
                    title="IP del receptor",
                    content=Label(text=f"Tu IP es: {ip}"),
                    size_hint=(0.6, 0.3)
                ).open()

            Clock.schedule_once(mostrar_ip, 0.5)  # Espera 0.5 segundos
        pedir_directorio_para_guardar(luego_de_elegir)


    def funcion_boton_derecho(self):
        print("Botón derecho pulsado")
        self.mostrar_seleccionador_archivo()


class MiApp(App):
    def build(self):
        Builder.load_file('EstiloM.kv')
        return MiVentana()


if __name__ == '__main__':
    MiApp().run()