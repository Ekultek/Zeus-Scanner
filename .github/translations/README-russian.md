[![GitHub stars](https://img.shields.io/github/stars/ekultek/zeus-scanner.svg?style=flat-square)](https://github.com/ekultek/zeus-scanner/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/ekultek/zeus-scanner.svg?style=flat-square)](https://github.com/ekultek/zeus-scanner/network) 
[![GitHub issues](https://img.shields.io/github/issues/ekultek/zeus-scanner.svg?style=flat-square)](https://github.com/ekultek/zeus-scanner/issues) 
[![GitHub license](https://img.shields.io/badge/license-GPL-blue.svg?style=flat-square)](https://raw.githubusercontent.com/Ekultek/Zeus-Scanner/master/.github/LICENSE.md)
[![Twitter](https://img.shields.io/twitter/url/https/github.com/ekultek/zeus-scanner.svg?style=social)](https://twitter.com/Zeus_Scanner)
[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://github.com/Ekultek/Zeus-Scanner#donations)

# Полезные ссылки каталог

- [Что такое Зевс](https://github.com/Ekultek/Zeus-Scanner#zeus-scanner)
- [Зевса е нкции](https://github.com/Ekultek/Zeus-Scanner#features)
- [Требования и установка](https://github.com/Ekultek/Zeus-Scanner#requirements)
 - [Ubuntu / Debian](https://github.com/Ekultek/Zeus-Scanner#ubuntudebian)
 - [CentOS](https://github.com/Ekultek/Zeus-Scanner#centos)
 - [другие](https://github.com/Ekultek/Zeus-Scanner#others)
- [Скриншоты](https://github.com/Ekultek/Zeus-Scanner#screenshots)
- [Demo видео](https://vimeo.com/239885768)
- [инструкцияэксплуатации](https://github.com/Ekultek/Zeus-Scanner/wiki)
 - [Как Зевс работает](https://github.com/Ekultek/Zeus-Scanner/wiki/How-Zeus-works)
 - [Функциональность](https://github.com/Ekultek/Zeus-Scanner/wiki/Functionality)
 - [Передача sqlmap флаги с Зевсом](https://github.com/Ekultek/Zeus-Scanner/wiki/Passing-flags-to-sqlmap)
- [Правовая информация](https://github.com/Ekultek/Zeus-Scanner/tree/master/.github)
 - [License (GPL)](https://github.com/Ekultek/Zeus-Scanner/blob/master/.github/LICENSE.md)
 - [Кодекс поведения](https://github.com/Ekultek/Zeus-Scanner/blob/master/.github/CODE_OF_CONDUCT.md)
- [Сообщить об ошибке](https://github.com/Ekultek/Zeus-Scanner/issues/new)
- [Открыть запрос нагрузочный](https://github.com/Ekultek/Zeus-Scanner/compare)
 - [руководящие принципы](https://github.com/Ekultek/Zeus-Scanner/blob/master/.github/CONTRIBUTING.md)
- [Пожертвования Зевса](https://github.com/Ekultek/Zeus-Scanner#donations)
- [Shoutouts](https://github.com/Ekultek/Zeus-Scanner#shoutouts)

# Zeus-сканер

### Что такое Зевс?

Зевс является утилитой разведки разработаночтобы сделать вебприложения разведывательный просто. Зевс поставляетсякомплекте с мощным встроенным URL разбора двигателя, множественная совместимости двигателя поиска, возможность извлечения URLадреса из обоих запрета и Webcache URLадресов, возможность запуска нескольких оценок уязвимости на цели, и может обойти каптч поисковой системы.

### Особенности

- мощная встроенная в URL разбора двигателя
- Совместимость Multiple поисковой системы (`DuckDuckGo`,` AOL`, `Bing`и` Google` умолчанию является `Google`)
- Возможность извлечения URL из запрета URLGoogle обходя таким образом IPблоки
- Возможность извлекать из Webcache URLGoogle
- проксисовместимость (`http`,` https`, `socks4`,` socks5`)
- совместимостьпроксиTor и эмуляция Tor браузера
- Разбираем `robots.txt`/`Карта сайта.xml` и сохранить их в файл
- оценки Множественные уязвимости (XSS, SQLI, ClickJacking, сканирование портов, админка находкой, Whois поиски, и многое другое)
- тампера скрипты запутать XSS полезных нагрузок
- Может работать с настраиваемойумолчанию агент пользователя , один из более чем 4000 случайных пользовательских агентов или личного агента пользователя
- Автоматическое создание проблемыкогда возникает неожиданная ошибка
- Возможность сканировать вебстраницу и вытащить все ссылки
- Может работать уникальный мужлан, несколько Dorks в данном файл, или случайный придурок из списка более 5000 тщательно исследовал Dorks
- Dork черный списоккогда сайты не найдены с поисковым запросом, будет сохранить запрос в черный список файлов
- Определение WAF / IPS / защита IDS более 20 различных брандмауэров
- защита перечисления заголовка для проверкичто вид защиты обеспечиваетсяпомощью HTTP заголовков
- Сохранение куки, заголовков и другая необходимая информация в логфайлы
- и многое другое ...

### Скриншоты

Запуск без обязательных опций, или запустив `--help` флаг будет выводить меню помощи Зевса:
[Zeus-помощь](https://user-images.githubusercontent.com/14183473/30176257-63391c62-93c7-11e7-94d7-68fde7818381.png)

основной мужлан сканирование с `-d` флагом, из данного мужлана запустит автоматизированную браузер и тянуть Google результаты страницы:
[Zeus-мужлан-сканирования](https://user-images.githubusercontent.com/14183473/30176252-618b191a-93c7-11e7-84d2-572c12994c4d.png)

Вызов `-s` флаг запросит вы начать API сервера sqlmap `питон sqlmapapi.py -s` из sqlmap, он будет подключаться к API и выполнить sqlmap сканирование на найденный URL.
[Zeus-sqlmap-апи](https://user-images.githubusercontent.com/14183473/30176259-6657b304-93c7-11e7-81f8-0ed09a6c0268.png)

Вы можете увидеть больше скриншотов [здесь](https://github.com/Ekultek/Zeus-Scanner/wiki/Screenshots)

### Demo

[![to_video](https://user-images.githubusercontent.com/14183473/31474224-feb8c022-aebe-11e7-9684-1ba83f4fd7ff.png)](https://vimeo.com/239885768)

### требования

Есть некоторые требования для этогочтобы быть успешно работать.

##### Основные требования

- `libxml2-dev`,` libxslt1-dev`, `питон-dev` необходимы для процесса установки
- веббраузер Firefox требуется как сейчас, вы будете нуждатьсяFirefox версии`<= 57 > = 51` (между 51 и 57).конечном итоге будет добавлена полная функциональность для других браузеров.
- Если вы хотите запустить sqlmap через вам нужно будет sqlmap URLгдето в вашей системе.
- Если вы хотите запустить сканирование портовпомощью Nmap по IPадресов URL. Вы будете нуждатьсяNmap в вашей системе.
- [Geckodriver](https://github.com/mozilla/geckodriver)требуется для запуска веббраузера Firefox и будет установлен в первый раз при запуске. Он будет добавлен к вашему `/ USR / bin` так что он может быть запущен в вашем ENV PATH.
- Вы должны быть `sudo` впервые работает это такчто вы можете добавить драйвер в PATH, вы можете также должны работать как`sudo` зависимости от ваших прав. _ПРИМЕЧАНИЕ:_ `зависимости от прав доступа может потребоваться быть Суда для любого бегаучастием geckodriver`
-` xvfb` требуется на `pyvirtualdisplay`,он будет установленесли не установлен на вашемпервого запуска

пакете Python##### требования

- [селен WebDriver](http://www.seleniumhq.org/projects/webdriver/)пакет требуется для автоматизации веббраузер и перепускной API вызовов.
- [запросы](http://docs.python-requests.org/en/master/)пакет требуется для подключения к URLадресу, а sqlmap API
- [питон-птар](http://xael.org/страницы /питон-птар-en.html)пакет требуется для запуска Nmap по IPадресам URL,
- [whichcraft](https://github.com/spookyowl/witchcraft)пакет требуетсячтобы проверитьесли птар и sqlmap находятся на вашем системыесли вы хотите использовать их
- [pyvirtualdisplay](https://pyvirtualdisplay.readthedocs.io/en/latest/)пакет требуетсячтобы скрыть экран браузеравремя нахождения поиска URL
- [LXML](https:// LXML .readthedocs.io / о / последние/)требуется для анализа данных XML длясайта и сохранить его как таковые
- [psutil](https://github.com/giampaolo/psutil)требуется для поиска работы sqlmap сессий API
- [BeautifulSoup](https://www.crummy.com/software/BeautifulSoup/bs4/doc/)требуетсячтобы вытащить все тег дескриптора HREF и разбор HTML в легко работоспособный синтаксисе

### Установку

Вы можете скачать последняя [tar.gz](https://github.com/ekultek/zeus-scanner/tarball/master),последняя [застежкамолния](https://github.com/ekultek/zeus-scanner/zipball/master),или вы можете найти ток стабильный релиз [здесь](https://github.com/Ekultek/Zeus-Scanner/releases/tag/v1.3).альтернативы вы можете установить последнюю версию развития, следуя инструкциикоторые наилучшимсоответствуют вашей операционной системе:

** _Примечание: (обязательноно настоятельно рекомендуется)_ ** добавить sqlmap и Nmap в вашу среде PATH, перемещая их в `/ USR / бен `илипутем добавления их в PATH через терминал

##### Ubuntu/Debian

```
sudo apt-get install libxml2-dev libxslt1-dev python-dev &&  git clone https://github.com/ekultek/zeus-scanner.git && cd zeus-scanner && sudo pip2 install -r requirements.txt && sudo python zeus.py
``` 
 
##### centOS

```
sudo apt-get install gcc python-devel libxml2-dev libxslt1-dev python-dev && git clone https://github.com/ekultek/zeus-scanner.git && cd zeus-scanner && sudo pip2 install -r requirements.txt && sudo python zeus.py
```

##### Others

```
sudo apt-get install libxml2-dev libxslt1-dev python-dev && git clone https://github.com/ekultek/zeus-scanner.git && cd zeus-scanner && sudo pip2 install -r requirements.txt && sudo python zeus.py
```

Этоустановит всеM. Требования GE вместе с geckodriver


### Пожертвования

Zeus создается небольшой группой разработчиков, у которых есть стремление к информационной безопасности и стремятся добиться успеха. Если вы хотите Зевс и хотите пожертвовать наше финансирование, мырадостью и благодарностью принимаем пожертвование через:

- Bitcoin (BTC): `3DAQGcAQ194NGVs16Mmv75ip45CVuE8cZy`
- [PayPal](https://www.paypal.me/ZeusScanner)
- Или вы можете [купить нам кофе](https://ko-fi.com/A28355P5)

Вы можете быть уверенычто все пожертвования пойдут на финансирование Зевсачтобы сделать его более надежным и даже лучше, спасибо от команды разработчиков Zeus

### Shoutouts

##### [OpenSource проекты](https://www.facebook.com/opensourceprojects/)

OpenSource проекты это страница Facebook сообществакто цель состоитчтобы дать разработчикам, новые и старые, а легко и просто месточтобы разделить их вклад OpenSource и проекты. Я лично считаюэто огромная идея, я знаюкак трудно получить код заметил людьми и поддерживает эти ребята100%. Идите вперед и дать им как [здесь](https://www.facebook.com/opensourceprojects/).Они будут делиться любой проектоткрытым исходным кодом вы отправить их бесплатно. Спасибо OpenSource проектов для предоставления разработчикам место для обмена работу друг с другом!

