import tkinter as tk
from PIL import Image, ImageTk
from tkinter import scrolledtext
import nmap
import threading
import time
# Funcion para realizar el escaneo
def escaneo(rango):
    escaner = nmap.PortScanner()
    escaner.scan(hosts=rango, arguments='-sn')
    ips_activas = [host for host in escaner.all_hosts() if escaner[host].state() == "up"]
    return ips_activas

#Interfaz del escaner
class InterfazEscaner:
    def __init__(self, ventana):
        self.ventana = ventana
        self.ventana.title("Escaner de red")
        self.ventana.geometry("370x500")

        ruta_imagen = 'img\logo-ite.png'
        imagen = Image.open(ruta_imagen)
        imagen_tk = ImageTk.PhotoImage(imagen)
        label_imagen = tk.Label(ventana, image=imagen_tk)
        label_imagen.image = imagen_tk  
        # Mantener referencia de la imagen
        label_imagen.place(x=0, y=0)  

        self.rango = tk.StringVar(value="192.168.0.1/24")
        self.segundos = tk.IntVar(value=10)
        self.escaneando = False
        self.escaneo_hilo = None
        self.previas_ip_activas = set()

        # Entrada para el rango de la red 
        tk.Label(ventana, text="Rango:").pack(pady=5)
        self.entrada_rango = tk.Entry(ventana, textvariable=self.rango, width=30)
        self.entrada_rango.pack(pady=5)
        
        tk.Label(ventana, text='Segundos para repetir el escaneo').pack()
        self.entrada_segundos = tk.Entry(ventana, textvariable = self.segundos)
        self.entrada_segundos.pack()

        # Boton de inicio y detencion
        self.boton_inicio = tk.Button(ventana, text="Iniciar Escaneo", command=self.boton_escaneo)
        self.boton_inicio.pack(pady=10)
        
        # Mostrar Ips
        tk.Label(ventana, text="IPs activas:").pack(pady=5)
        self.imprimir_ip = scrolledtext.ScrolledText(ventana, width=40, height=10)
        self.imprimir_ip.pack(pady=5)
    
    def boton_escaneo(self):
        if not self.escaneando:
            # Inicio del escaneo 
            self.escaneando = True
            self.boton_inicio.config(text="Detener")
            self.imprimir_ip.delete(1.0, tk.END)  # Limpiamos el area del  texto
            self.escaneo_hilo = threading.Thread(target=self.reescaneo)
            self.escaneo_hilo.start()
        else:
            # Fin del escaneo
            self.escaneando = False
            self.boton_inicio.config(text="Iniciar")
            if self.escaneo_hilo is not None:
                self.escaneo_hilo.join() 

    def reescaneo(self):
        rango = self.rango.get()
        segundos = self.segundos.get()
        
        while self.escaneando:
            # Realiza el escaneo y lo almacenamos en en ip_actuales
            ip_actuales = set(escaneo(rango))
            
            # Update text area with color-coded results
            self.imprimir_ip.delete(1.0, tk.END)  # Limpia el contenido actual
            
            # Mostrar Ips activas 
            for ip in ip_actuales:
                self.imprimir_ip.insert(tk.END, f"{ip}\n", "active")
            
            # Mostrar las ips que estaban conectadas, ahora inactivas
            ip_inactivas = self.previas_ip_activas - ip_actuales
            for ip in ip_inactivas:
                self.imprimir_ip.insert(tk.END, f"{ip} (Desconectado)\n", "inactive")
            
            # Jalamos las ips antiguas a las ips previas para la siguiente comparacion
            self.previas_ip_activas = ip_actuales
            
            # Colores
            self.imprimir_ip.tag_config("active", foreground="green")
            self.imprimir_ip.tag_config("inactive", foreground="gray")
            
            # tiempo de espera
            time.sleep(segundos)

# Configuracion inicial
ventana = tk.Tk()
app = InterfazEscaner(ventana)
ventana.mainloop()
