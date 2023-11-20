[![GitHub stars](https://img.shields.io/github/stars/ekultek/zeus-scanner.svg?style=flat-square)](https://github.com/ekultek/zeus-scanner/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/ekultek/zeus-scanner.svg?style=flat-square)](https://github.com/ekultek/zeus-scanner/network)
[![GitHub issues](https://img.shields.io/github/issues/ekultek/zeus-scanner.svg?style=flat-square)](https://github.com/ekultek/zeus-scanner/issues)
[![GitHub license](https://img.shields.io/badge/license-GPL-blue.svg?style=flat-square)](https://raw.githubusercontent.com/Ekultek/Zeus-Scanner/master/.github/LICENSE.md)
[![Twitter](https://img.shields.io/twitter/url/https/github.com/ekultek/zeus-scanner.svg?style=social)](https://twitter.com/Zeus_Scanner)
[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://github.com/Ekultek/Zeus-Scanner#donations)

# Annuaire des liens utiles

- [Qu'estce que Zeus](https://github.com/Ekultek/Zeus-Scanner#zeus-scanner)
- [Les caractéristiques de Zeus](https://github.com/Ekultek/Zeus-Scanner#features)
- [Exigences et installation](https://github.com/Ekultek/Zeus-Scanner#requirements)
  - [Ubuntu/Debian](https://github.com/Ekultek/Zeus-Scanner#ubuntudebian)
  - [centOS](https://github.com/Ekultek/Zeus-Scanner#centos)
  - [autre](https://github.com/Ekultek/Zeus-Scanner#others)
- [Capturesécran](https://github.com/Ekultek/Zeus-Scanner#screenshots)
- [vidéo Demo](https://vimeo.com/239885768)
- [manuel d'utilisation](https://github.com/Ekultek/Zeus-Scanner/wiki)
  - [Comment fonctionne Zeus](https://github.com/Ekultek/Zeus-Scanner/wiki/How-Zeus-works)
  - [Fonctionnalité](https://github.com/Ekultek/Zeus-Scanner/wiki/Functionality)
  - [Passant drapeaux sqlmap avec Zeus](https://github.com/Ekultek/Zeus-Scanner/wiki/Passing-flags-to-sqlmap)
- [Informations légales](https://github.com/Ekultek/Zeus-Scanner/tree/master/.github)
  - [Licence (GPL)](https://github.com/Ekultek/Zeus-Scanner/blob/master/.github/LICENSE.md)
  - [Code de conduite](https://github.com/Ekultek/Zeus-Scanner/blob/master/.github/CODE_OF_CONDUCT.md)
- [Signaler un bug](https://github.com/Ekultek/Zeus-Scanner/issues/new)
- [Ouvrir une demande de traction](https://github.com/Ekultek/Zeus-Scanner/compare)
  - [lignes directrices de contribution](https://github.com/Ekultek/Zeus-Scanner/blob/master/.github/CONTRIBUTING.md)
- [Dons à Zeus](https://github.com/Ekultek/Zeus-Scanner#donations)
- [Shoutouts](https://github.com/Ekultek/Zeus-Scanner#shoutouts)

# Zeus-Scanner

### Qu'estce que Zeus?

Zeus est un utilitaire de reconnaissance avancée conçue pour rendreapplication web simple de reconnaissance. Zeus est livré avec une puissante compatibilité intégrée dansmoteur,moteur de recherche multiple analyse syntaxique URL, la capacité d'extraireURL des deux URL interdiction et WebCache, la possibilité d'exécuter plusieurs évaluations devulnérabilité sur la cible, et estmesure de contournermoteur de recherche captchas.

### Caractéristiques

- Un puissant construit dansmoteur d'analyse syntaxique URL
- compatibilité des moteurs de recherche multiples (`DuckDuckGo`,` AOL`, `Bing`et`  défaut est `Google`Google`)
- Possibilité d'extraire l'URL de l'URL d'interdiction de Google contournant ainsiblocs IP
- Possibilité d'extraire l'URL de webcache Google
- compatibilité proxy (`http`,` https`, `socks4`,` socks5`)
- compatibilité proxy Tor etémulation de navigateur Tor
- Parse `robots.txt`/`plansite .xml` et les enregistrer dans un fichier
- évaluations devulnérabilité multiples (XSS, SQLi, clickjacking, balayageports, panneau d'administration découverte,recherches whois et plus)
- sabotage scripts pour occultent XSS charges utiles
- Peut fonctionner avec un agent utilisateurdéfaut personnalisé ,un des plus4000 agents-utilisateurshasard, ou un agent utilisateur personnel
- création d'émission automatique lorsqu'une erreur inattendue survient
- Capacité d'analyser une page Web et tirer tous les liens
- Peut exécuter un dork singulier, dorks multiples dans un fichier donné, ou un dorkhasard dans une liste de plus5000 dorks soigneusement étudiés
- dork listes noires lorsque passites se trouvent à la requête de recherche, va enregistrer la requête dans un fichier liste noire
- Identifierprotection WAF / IPS / IDS de plus20 différents parefeu
- énumération de protectiontête pour vérifier quel type de protection est assurée partêtes HTTP
- enregistrementcookies,têtes etautres informations vitales pourfichiers journaux
- et bien plus encore ...

### Capturesécran

Exécution sans options obligatoires, ouexécuter le --help` `drapeauva afficher le menu d'aide de Zeus:
[zeus-help](https://user-images.githubusercontent.com/14183473/30176257-63391c62-93c7-11e7-94d7-68fde7818381.png)

un dorkbase avec le `balayage-d`, drapeau  du dork donné lancera un navigateur automatisé et tirer le Google résultats page:
[zeus-dork-scan](https://user-images.githubusercontent.com/14183473/30176252-618b191a-93c7-11e7-84d2-572c12994c4d.png)

Appeler le `-s` drapeauvous demandera vous de démarrer le serveur API sqlmap `python sqlmapapi.py -s` de sqlmap, il va alorsconnecter à l'API et effectuer une analyse de sqlmap sur les URL trouvées.
[zeus-sqlmap-api](https://user-images.githubusercontent.com/14183473/30176259-6657b304-93c7-11e7-81f8-0ed09a6c0268.png)

Vous pouvez voir pluscapturesécran [ici](https://github.com/Ekultek/Zeus-Scanner/wiki/Screenshots)

###[Demo!

[![to_video](https://user-images.githubusercontent.com/14183473/31474224-feb8c022-aebe-11e7-9684-1ba83f4fd7ff..png)](https://vimeo.com/239885768)

### exigences

Il y a des exigences pourcela soit exécutésuccès.

##### Exigencesbase

- `libxml2-dev`,` libxslt1-dev`, `python-dev` sont nécessaires pour le processus d'installation
- navigateur web Firefox est nécessairepartir de maintenant, vous aurez besoin Firefox version`<= 57 > = 51` (entre 51 et 57).fonctionnalité complète pourautres navigateurs seront ajoutées.
- Si vous voulez exécuter sqlmaptravers vous aurez besoin d'sqlmap quelque part de l'URL sur votre système.
- Si vous voulez exécuter un port numérisationaide nmap sur les adresses IP de l'URL. Vous aurez besoin nmap sur votre système.
- [Geckodriver](https://github.com/mozilla/geckodriver)est nécessaire pour exécuter le navigateur Web Firefox et sera installé la première foisvous exécutez. Il sera ajouté à votre `/ usr / bin` afin qu'il puisse être exécuté dans votre ENV PATH.
- Vous devez être `sudo` pour la première foiscoursexécutioncette façon que vous pouvez ajouter le pilote à votre PATH, vous devrez peutêtre exécutertant que`sudo` fonction de vos autorisations. _REMARQUE:_ `fonction des autorisationsvous devrez peutêtre pour toute exécution sudo impliquant le geckodriver`
-` xvfb` est requis par `pyvirtualdisplay`,il sera installécasinstallation sur votre premier run

##### package Python exigences

- [sélénium WebDriver](http://www.seleniumhq.org/projects/webdriver/)paquet est nécessaire pour automatiser les appels API de navigateur Web et bypass.
- [demandes](http://docs.python-requests.org/en/master/)paquet  est nécessaire pourconnecter à l'URL, et l'API sqlmap
- [-nmap python](http://xael.org/pages/python-nmap-fr.html)paquet  est nécessaire pour exécuter nmap sur les adresses IP de l'URL
- [Whichcraft](https://github.com/spookyowl/witchcraft)package est nécessaire pour vérifier si nmap et sqlmap sont sur votre système si vous voulez les utiliser
- [pyvirtualdisplay](https://pyvirtualdisplay.readthedocs.io/en/latest/)package  est nécessaire pour masquer l'affichage du navigateur touttrouvant l'URL de recherche
- [lxml](https://lxml.readthedocs.io/fr/latest/)est nécessaire pour analyserdonnées XML pour le plansite etenregistrertant que tel
- [psutil](https://github.com/giampaolo/psutil)est nécessaire pour rechercherexécutionsessions API sqlmap
- [beautifulsoup](https://www.crummy.com/software/BeautifulSoup/bs4/doc/)est nécessaire pour tirer toutes les balises de descripteur HREF et analyser le code HTML dans une syntaxe facilement réalisable

### Installation

Vous pouvez télécharger le dernière [tar.gz](https://github.com/ekultek/zeus-scanner/tarball/master),le dernier [zip](https://github.com/ekultek/zeus-scanner/zipball/master),ou vous pouvez trouver le courant version stable [ici](https://github.com/Ekultek/Zeus-Scanner/releases).Sinonvous pouvez installer la dernière version de développement en suivant les instructions qui correspondentmieux à votre système d'exploitation:

** _NOTE: (facultatif mais fortement conseillé)_ ** ajouter sqlmap et nmap à votre environnement PATH en les déplaçant vers `/usr/bin `ouen les ajoutant au PATH viaterminal

##### Ubuntu/Debian

```shell
sudo apt install libxml2-dev libxslt1-dev python-dev firefox && \
git clone https://github.com/ekultek/zeus-scanner.git && \
cd zeus-scanner && \
sudo pip3 install -r requirements.txt && \
sudo python3 zeus.py
```

##### centOS

```shell
sudo yum install gcc libxml2-dev libxslt1-dev python-devel firefox && \
git clone https://github.com/ekultek/zeus-scanner.git && \
cd zeus-scanner && \
sudo pip3 install -r requirements.txt && \
sudo python3 zeus.py
```

##### Others

```shell
sudo apt install libxml2-dev libxslt1-dev python-dev firefox && \
git clone https://github.com/ekultek/zeus-scanner.git && \
cd zeus-scanner && \
sudo pip3 install -r requirements.txt && \
sudo python3 zeus.py
```

Celainstallera tous les Packa exigences ge ainsi que les geckodriver


### Dons

Zeus est créé par une petite équipe de développeurs qui ont une aspiration àsécurité deinformation et cherchent à réussir. Si vous aimez Zeus etvous voulez fairedon à notre financement, nous acceptons avec plaisir et appréciateur dons via:

- Bitcoin (BTC): `3DAQGcAQ194NGVs16Mmv75ip45CVuE8cZy`
- [PayPal](https://www.paypal.me/ZeusScanner)
- Vous pouvez [Achètenous un café](https://ko-fi.com/A28355P5)

vous pouvez être assuré que tousdons serviront au financementZeus pourrendre plus fiable et mieux encore, merci de l'équipe de développement Zeus

### Shoutouts

##### [OpenSource Projets](https://www.facebook.com/opensourceprojects/)

OpenSource Projects est une page communautaire Facebook qui abut est de donnerdéveloppeurs, nouveaux et anciens, un endroit facile et simple de partager leur contributions opensource etprojets. Personnellementje pensec'est une idée géniale, je sais combien il est difficile d'obtenir votre code remarqué pargens et soutenir ces garslà100%. Allezy et leur donner un comme [ici](https://www.facebook.com/opensourceprojects/).Ils partageront tout projet opensourcevous leur envoyez gratuitement. Merci projets OpenSource pour donnerdéveloppeurs un endroit pour partagertravail avec un autre!

