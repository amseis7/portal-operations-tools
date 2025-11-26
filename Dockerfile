# 1. Usamos una imagen base de Python oficial (ligera)
FROM python:3.11-slim

# 2. Variable Mágica: Obliga a mostrar los logs inmediatamente
ENV PYTHONUNBUFFERED=1

# 3. Establecemos el directorio de trabajo dentro del contenedor
WORKDIR /app

# 4. Copiamos el archivo de requisitos primero (para aprovechar la caché de Docker)
COPY requirements.txt .

# 5. Instalamos las dependencias (incluyendo waitress)
RUN pip install --no-cache-dir -r requirements.txt

# 6. Copiamos todo el resto del código de tu carpeta al contenedor
COPY . .

# 7. Exponemos el puerto 8080 (el que usa Waitress)
EXPOSE 8080

# 8. El comando que se ejecuta al iniciar el contenedor
CMD ["python", "server.py"]