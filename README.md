# revShell

<p align="center">
  <img src="#" alt="revShell" width="400">
</p>

## Descripción

**revShell** es una herramienta poderosa y versátil para generar varios tipos de shells inversos (reverse shells) en múltiples lenguajes de programación. Esta herramienta facilita la generación rápida y eficiente de comandos de reverse shell, proporcionando diferentes métodos y opciones para diversas situaciones y entornos.

## Funcionalidades

`revShell` soporta la generación de reverse shells en los siguientes lenguajes y entornos:

- **PHP**: Utiliza diferentes métodos como `exec`, `shell_exec`, `system`, `passthru`, `popen`, `proc_open`.
- **PowerShell**: Proporciona múltiples variantes, incluyendo conexiones encriptadas con TLS.
- **Python**: Compatible con versiones 2.x y 3.x, usando sockets y `pty`.
- **Ruby**: Shells con y sin uso de `sh`.
- **socat**: Con soporte para TTY.
- **SQLite3 y netcat**: Uso combinado para crear shells inversos.
- **node.js**: Utilizando el módulo `child_process`.
- **Groovy**: Utiliza sockets y `ProcessBuilder`.
- **telnet**: Shell inverso utilizando `telnet`.
- **zsh**: Usando `zmodload` y `ztcp`.
- **Lua**: Con `socket` y `os` módulos.
- **Golang**: Shell inverso utilizando `net` y `os/exec`.
- **Vlang**: Utilizando `os.system`.
- **Awk**: Usando sockets inet.
- **Dart**: Usando `dart:io` y `dart:convert`.
- **Crystal**: Utilizando `process` y `socket`.

## Instalación

Para instalar y configurar `revShell`, sigue los pasos a continuación:

### Clona el Repositorio

```bash
git clone https://github.com/D1se0/revShell.git
cd revShell
```

### Ejecuta el Script de Requisitos

El script requirements.sh instalará todas las dependencias necesarias y configurará la herramienta para que pueda ser utilizada desde cualquier lugar en la terminal.

```bash
sudo ./requirements.sh
```

### Verifica la Instalación

Después de ejecutar el script de requisitos, verifica que la herramienta está instalada correctamente:

```bash
revShell -h
```
o desde el script `.py`

```bash
python3 revShell.py -h
```

## Uso

`revShell` es extremadamente fácil de usar. A continuación, se presentan algunos ejemplos de cómo generar diferentes tipos de reverse shells.

```bash
python3 revShell.py -i <IP_HOST> -p <PORT> -t <FORMAT>
```

### Ejemplos

Generar un Reverse Shell en bash:

```bash
python3 revShell.py -i 10.10.11.11 -p 7777 -t 'bash -i'
```

Generar un Reverse Shell en PHP:

```bash
python3 revShell.py -i 10.10.11.11 -p 7777 -t 'PHP proc_open'
```

Generar un Reverse Shell en PowerShell:

```bash
python3 revShell.py -i 10.10.11.11 -p 7777 -t 'PowerShell #1'
```

Generar un Reverse Shell en Python:

```bash
python3 revShell.py -i 10.10.11.11 -p 7777 -t 'Python #1'
```

Generar un Reverse Shell en Ruby:

```bash
python3 revShell.py -i 10.10.11.11 -p 7777 -t 'Ruby #1'
```

Otras Opciones:

`revShell` soporta muchas más opciones y lenguajes. Para ver todas las opciones disponibles:

```bash
python3 revShell.py -fh
```

## Contribuciones

Las contribuciones son bienvenidas. Por favor, envía un `pull request` o abre un `issue` para discutir los cambios que te gustaría realizar.

## Licencia

Este proyecto está licenciado bajo los términos de la licencia MIT.
