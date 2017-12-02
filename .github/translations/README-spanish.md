[![GitHub stars](https://img.shields.io/github/stars/ekultek/zeus-scanner.svg?style=flat-square)](https://github.com/ekultek/zeus-scanner/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/ekultek/zeus-scanner.svg?style=flat-square)](https://github.com/ekultek/zeus-scanner/network) 
[![GitHub issues](https://img.shields.io/github/issues/ekultek/zeus-scanner.svg?style=flat-square)](https://github.com/ekultek/zeus-scanner/issues) 
[![GitHub license](https://img.shields.io/badge/license-GPL-blue.svg?style=flat-square)](https://raw.githubusercontent.com/Ekultek/Zeus-Scanner/master/.github/LICENSE.md)
[![Twitter](https://img.shields.io/twitter/url/https/github.com/ekultek/zeus-scanner.svg?style=social)](https://twitter.com/Zeus_Scanner)
[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://github.com/Ekultek/Zeus-Scanner#donations)

# Directorio de enlaces útiles

- [Qué es Zeus](https://github.com/Ekultek/Zeus-Scanner#zeus-scanner)
- [Funciones de Zeus](https://github.com/Ekultek/Zeus-Scanner#features)
- [Requisitos e instalación](https://github.com/Ekultek/Zeus-Scanner#requirements)
  - [Ubuntu/Debian](https://github.com/Ekultek/Zeus-Scanner#ubuntudebian)
  - [centOS](https://github.com/Ekultek/Zeus-Scanner#centos)
  - [otro](https://github.com/Ekultek/Zeus-Scanner#others)
- [Capturas de pantalla](https://github.com/Ekultek/Zeus-Scanner#screenshots)
- [Video de demostración](https://vimeo.com/239885768)
- [Manual de usuario](https://github.com/Ekultek/Zeus-Scanner/wiki)
  - [Cómo funciona Zeus](https://github.com/Ekultek/Zeus-Scanner/wiki/How-Zeus-works)
  - [Funcionalidad](https://github.com/Ekultek/Zeus-Scanner/wiki/Functionality)
  - [Pasando banderas sqlmap con Zeus](https://github.com/Ekultek/Zeus-Scanner/wiki/Passing-flags-to-sqlmap)
- [Información legal](https://github.com/Ekultek/Zeus-Scanner/tree/master/.github)
  - [Licencia (GPL)](https://github.com/Ekultek/Zeus-Scanner/blob/master/.github/LICENSE.md)
  - [Código de conducta](https://github.com/Ekultek/Zeus-Scanner/blob/master/.github/CODE_OF_CONDUCT.md)
- [Informar de un error](https://github.com/Ekultek/Zeus-Scanner/issues/new)
- [Abrir solicitud de extracción](https://github.com/Ekultek/Zeus-Scanner/compare)
  - [Directrices de contribución](https://github.com/Ekultek/Zeus-Scanner/blob/master/.github/CONTRIBUTING.md)
- [Donaciones a Zeus](https://github.com/Ekultek/Zeus-Scanner#donations)
- [Shoutouts](https://github.com/Ekultek/Zeus-Scanner#shoutouts)

# Zeus-Scanner

### ¿Qué es Zeus?

Zeus es una utilidad de reconocimiento avanzada diseñada para hacer que el reconocimiento de aplicaciones web sea simple. Zeus viene completo con un poderoso motor de análisis integrado de URL, compatibilidad con múltiples motores de búsqueda, la capacidad de extraer URL de las URL de prohibición y de caché web, la capacidad de ejecutar múltiples evaluaciones de vulnerabilidad en el objetivo y puede eludir los captchas de los motores de búsqueda.

### Caracteristicas

 - Un potente motor de análisis de URL incorporado
 - La compatibilidad con múltiples motores de búsqueda (`DuckDuckGo`,` AOL`, `Bing` y` Google` por defecto es `Google`
 - Posibilidad de extraer la URL de la URL de prohibición de Google evitando así los bloques de IP
 - Posibilidad de extraer de la URL de caché web de Google
 - Compatibilidad proxy (`http`,` https`, `socks4`,` socks5`
 - Compatibilidad Tor proxy y emulación de navegador Tor
 - Parse `robots.txt` /` sitemap.xml` y guárdelos en un archivo
 - Múltiples evaluaciones de vulnerabilidad (XSS, SQLi, clickjacking, escaneo de puertos, hallazgos de panel de administración, búsquedas de whois, y más)
 - Guiones de sabotaje para ofuscar cargas útiles XSS
 - Se puede ejecutar con un agente de usuario predeterminado personalizado, uno de los más de 4000 agentes de usuario aleatorios o un agente de usuario personal
 - Creación automática de problemas cuando surge un error inesperado
 - Posibilidad de rastrear una página web y extraer todos los enlaces
 - Puede ejecutar un dork singular, múltiples dorks en un archivo determinado, o un dork aleatorio de una lista de más de 5000 dorks cuidadosamente investigados
 - Lista negra de Dork cuando no se encuentran sitios con la consulta de búsqueda, guardará la consulta en un archivo de lista negra
 - Identificar la protección WAF / IPS / IDS de más de 20 firewalls diferentes
 - Enumeración de protección de encabezado para verificar qué tipo de protección se proporciona a través de encabezados HTTP
 - Guardar cookies, encabezados y otra información vital para registrar archivos
 - y mucho más...

### Capturas de pantalla

Si ejecuta sin opciones obligatorias o si ejecuta el indicador `--help`, se mostrará el menú de ayuda de Zeus:
! [zeus-help](https://user-images.githubusercontent.com/14183473/30176257-63391c62-93c7-11e7-94d7-68fde7818381.png)
Un escaneo de dork básico con la bandera `-d`, del dork dado lanzará un navegador automatizado y extraerá los resultados de la página de Google:
! [zeus-dork-scan](https://user-images.githubusercontent.com/14183473/30176252-618b191a-93c7-11e7-84d2-572c12994c4d.png)
Llamar al indicador `-s` le pedirá que inicie el servidor de la API sqlmap` python sqlmapapi.py -s` desde sqlmap, luego se conectará a la API y realizará un análisis de sqlmap en la URL encontrada.
! [zeus-sqlmap-api](https://user-images.githubusercontent.com/14183473/30176259-6657b304-93c7-11e7-81f8-0ed09a6c0268.png)

Puede ver más capturas de pantalla [aquí](https://github.com/Ekultek/Zeus-Scanner/wiki/Screenshots)

### Demo

[![to_video](https://user-images.githubusercontent.com/14183473/31474224-feb8c022-aebe-11e7-9684-1ba83f4fd7ff.png)
](https://vimeo.com/239885768)

### Requisitos

Hay algunos requisitos para que esto se ejecute con éxito.

##### Requerimientos básicos

 - `libxml2-dev`,` libxslt1-dev`, `python-dev` son necesarios para el proceso de instalación
 - Se requiere navegador web Firefox a partir de ahora, necesitarás la versión de Firefox `<= 57> = 51` (entre 51 y 57). Se agregará la funcionalidad completa para otros navegadores.
 - Si desea ejecutar sqlmap a través de la URL, necesitará sqlmap en algún lugar de su sistema.
 - Si desea ejecutar un escaneo de puertos usando nmap en las direcciones IP de la URL. Necesitarás nmap en tu sistema.
 - [Geckodriver](https://github.com/mozilla/geckodriver) es necesario para ejecutar el navegador web firefox y se instalará la primera vez que ejecute. Se agregará a su `/ usr / bin` para que pueda ejecutarse en su ENV PATH.
 - Debe ser `sudo` por primera vez ejecutando esto para que pueda agregar el controlador a su RUTA, también puede necesitar ejecutar como` sudo` dependiendo de sus permisos. _NOTA: _`Dependiendo de los permisos, puede que necesite sudo para cualquier ejecución que involucre al geckodriver`
 - `xvfb` es requerido por` pyvirtualdisplay`, se instalará si no está instalado en su primera ejecución
 
##### Requisitos del paquete de Python

 - Se requiere el paquete [selenium-webdriver](http://www.seleniumhq.org/projects/webdriver/) para automatizar el navegador web y eludir las llamadas API.
 - Se requiere el paquete [requests](http://docs.python-requests.org/en/master/) para conectarse a la URL y a la API de sqlmap.
 - Se requiere el paquete [python-nmap](http://xael.org/pages/python-nmap-en.html) para ejecutar nmap en las direcciones IP de la URL
 - El paquete [witchcraft](https://github.com/spookyowl/witchcraft) es necesario para verificar si nmap y sqlmap están en su sistema si desea usarlos
 - Se requiere el paquete [pyvirtualdisplay](https://pyvirtualdisplay.readthedocs.io/en/latest/) para ocultar la visualización del navegador mientras se encuentra la URL de búsqueda
 - [lxml](https://lxml.readthedocs.io/en/latest/) es necesario para analizar los datos XML del mapa del sitio y guardarlo como tal
 - [psutil](https://github.com/giampaolo/psutil) es necesario para buscar ejecutar sesiones API de sqlmap
 - [beautifulsoup](https://www.crummy.com/software/BeautifulSoup/bs4/doc/) es necesario para extraer todas las etiquetas de descriptor HREF y analizar el HTML en una sintaxis fácil de usar
 
### Instalación

Puede descargar la última [tar.gz](https://github.com/ekultek/zeus-scanner/tarball/master), la última [zip](https://github.com/ekultek/zeus-scanner/zipball/master), o puede encontrar la versión estable actual [aquí](https://github.com/Ekultek/Zeus-Scanner/releases/tag/v1.3). Alternativamente, puede instalar la última versión de desarrollo siguiendo las instrucciones que mejor se adapten a su sistema operativo:

**_NOTA: (opcional pero muy recomendable)_ ** agregue sqlmap y nmap a su RUTA del entorno moviéndolos a `/usr/bin` o agregándolos a la RUTA a través de la terminal

##### Ubuntu / Debian

```
sudo apt-get install libxml2-dev libxslt1-dev python-dev && git clon https://github.com/ekultek/zeus-scanner.git y& cd zeus-scanner && sudo pip2 install -r requirements.txt && sudo python zeus .py
```
 
##### centOS

```
sudo apt-get install gcc python-devel libxml2-dev libxslt1-dev python-dev && git clon https://github.com/ekultek/zeus-scanner.git y& cd zeus-scanner && sudo pip2 install -r requirements.txt && sudo python zeus.py
```

##### Otros

```
sudo apt-get install libxml2-dev libxslt1-dev python-dev && git clon https://github.com/ekultek/zeus-scanner.git y& cd zeus-scanner && sudo pip2 install -r requirements.txt && sudo python zeus .py
```

Esto instalará todos los requisitos del paquete junto con el geckodriver

### Donaciones

Zeus es creado por un pequeño equipo de desarrolladores que aspiran a la seguridad de la información y se esfuerzan por tener éxito. Si te gusta Zeus y quieres donar a nuestra financiación, agradecemos y agradecemos las donaciones a través de:

 - Bitcoin (BTC): `3DAQGcAQ194NGVs16Mmv75ip45CVuE8cZy`
 - [PayPal](https://www.paypal.me/ZeusScanner)
 - O puedes [Cómpranos un café](https://ko-fi.com/A28355P5)
 
Puede estar seguro de que todas las donaciones se destinarán a la financiación de Zeus para que sea más confiable e incluso mejor, gracias del equipo de desarrollo de Zeus.

### Shoutsouts

##### [Proyectos de OpenSource](https://www.facebook.com/opensourceprojects/)

OpenSource Projects es una página de la comunidad de Facebook cuyo objetivo es brindar a los desarrolladores, nuevos y antiguos, un lugar fácil y simple para compartir sus contribuciones y proyectos de código abierto. Personalmente creo que esta es una idea increíble, sé lo difícil que es hacer que la gente note su código y apoyar a estos tipos al 100%. Continúa y dales un me gusta [aquí](https://www.facebook.com/opensourceprojects/). Compartirán cualquier proyecto de código abierto que les envíe de forma gratuita. ¡Gracias OpenSource Projects por darles a los desarrolladores un lugar para compartir el trabajo entre ellos!