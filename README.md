## Virus Scanner Bot (Telegram & Discord)

## Ce projet est un bot multi-plateformes (Telegram et Discord) conçu pour analyser des fichiers via VirusTotal. Les utilisateurs peuvent envoyer des fichiers au bot, qui les télécharge et les soumet à l'API de VirusTotal pour analyse. Ensuite, un rapport est généré et un résumé est envoyé à l'utilisateur indiquant le niveau de sécurité du fichier, accompagné d'une capture d'écran du rapport de VirusTotal.
Fonctionnalités principales
## Version Telegram :

    L'utilisateur peut envoyer un fichier (exécutable ou autre) directement au bot Telegram.
    Le bot télécharge le fichier, le soumet à VirusTotal pour analyse, puis récupère le rapport.
    Un pourcentage de sécurité est calculé en fonction du nombre de détections.
    Le bot génère une capture d'écran du rapport VirusTotal et l'envoie à l'utilisateur.

## Version Discord :

    Les utilisateurs peuvent mentionner le bot avec un fichier joint (exécutable ou autre).
    Le bot télécharge le fichier, effectue une analyse via VirusTotal, puis génère un rapport.
    Comme pour Telegram, un pourcentage de sécurité est calculé, et un résumé avec une capture d'écran du rapport est envoyé dans un embed Discord.

## Captures d'écran
- Exemple sur Telegram :
![image](https://github.com/user-attachments/assets/ae6b4360-7816-430d-8833-462f9d6b7a11)

- Exemple sur Discord :
  ![image](https://github.com/user-attachments/assets/49523d05-4bbc-4383-a2a7-01ac9916edeb)


## Installation

Ce projet utilise Node.js et nécessite plusieurs modules pour fonctionner. Voici les étapes pour installer les deux versions du bot.
Prérequis :

    Node.js (version 16.x ou supérieure)
    Un compte Telegram avec un bot créé via BotFather
    Un serveur Discord avec un bot créé via le Portail développeur Discord
Les modules requis :
- npm install node-telegram-bot-api discord.js axios form-data puppeteer
