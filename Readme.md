Trilogía
Trilogy es una biblioteca cliente para servidores de bases de datos compatibles con MySQL, diseñada para brindar rendimiento, flexibilidad y facilidad de integración.

Actualmente está en uso de producción en github.com.

Características
Admite las partes del protocolo de texto que se utilizan con más frecuencia

Apretón de manos
Autenticación de contraseña
Comandos de consulta, ping y salida
API de protocolo de bajo nivel completamente desacoplada de IO

API de cliente sin bloqueo que envuelve la API de protocolo

API de cliente de bloqueo que envuelve la API sin bloqueo

Sin dependencias fuera de POSIX y la biblioteca estándar de C

Asignación dinámica mínima

Con licencia del MIT

Limitaciones
Solo admite las partes del protocolo de texto que son de uso común. No hay soporte para el protocolo binario o declaraciones preparadas.

Sin soporte para LOAD DATA INFILEarchivos locales

trilogy_escape asume una codificación de conexión compatible con ASCII

Edificio
make- Eso es. Esto construirá una estáticalibtrilogy.a

Trilogy debería integrarse desde el primer momento en la mayoría de los sistemas UNIX que tienen OpenSSL instalado.

Documentación de API
La documentación de las diversas API de Trilogy se puede encontrar en estos archivos de encabezado:

blocking.h

La API del cliente de bloqueo. Estos son simplemente un conjunto de funciones de envoltura convenientes alrededor de la API del cliente sin bloqueo enclient.h

client.h

La API de cliente sin bloqueo. Cada comando se divide en una función _sendy _recv, lo que permite a las personas que llaman esperar la preparación de IO externamente a Trilogy.

builder.h

API de creación de paquetes compatible con MySQL

charset.h

Tablas de codificación y juego de caracteres

error.h

Tabla de errores. Cada función de Trilogy que devuelve un intusa los códigos de error definidos aquí

packet_parser.h

Analizador de tramas de paquetes de transmisión

protocol.h

API de protocolo de bajo nivel. Proporciona funciones desacopladas de IO para analizar y crear paquetes

reader.h

API de lector de paquetes con límites comprobados

Fijaciones
Mantenemos un enlace Ruby en este repositorio. Actualmente es estable y está listo para producción.

Licencia
Trilogy se lanza bajo la licencia MIT .
