# SecureSphere (WIP)
Application de Chat Sécurisée développé en Python avec des sockets et SSL/TLS.
Projet réalisé par Guillaume ROUSSELIN, Joseph BENARD, Emy LIM, Raphael Antoine Marie EDZIMBI, Antoine PUTÉANUS-MAUTINO
Equipe 10 - Sécurité Réseau

## Table des Matières

1. [Introduction](#introduction)
2. [Fonctionnalités](#fonctionnalités)
3. [Installation](#installation)
4. [Utilisation](#utilisation)
5. [Release Note](#release-note)


## Introduction
Le projet ChatSec a été réalisé dans le cadre du Mastercamp 2024 à l'EFREI.

Le projet vise à développer une application qui permet aux utilisateurs et aux entreprises
d'échanger des messages et des fichiers de manière sécurisée dans un chat, tout en offrant
une gestion fiable des droits et des connexions.


## Fonctionnalités
1- Client :
  - Vérification du certificat envoyé par le serveur
  - Inscription
  - Connexion
  - Voir les utilisateurs connectés
  - Envoyer des messages globals encryptés
  - Voir les messages
  - Envoyer des messages privés (DMs)
  - Se déconnecter

2- Serveur :
  - Lancement de l'application :
      - Envoi de clef public et certificat au client pour communication sécurisé
  - Inscription:
      - Vérifier la disponibilité du nom d'utilisateur
      - Hacher le mot de passe avec argon2 et enregistrer le sel utilisé
      - Enregistrer le nom d'utilisateur et le mot de passe dans la base de données
  - Connexion :
      - Vérifier l'existence du nom d'utilisateur dans la base de données
      - Hacher le mot de passe (avec le même sel)
      - Vérifier la concordance des informations avec celles enregistrés
  - Discussion :
      - Chiffrage et déchiffrage des messages échangés par les utilisateurs
  - Logs :
      - Sauvegarde des tentatives de communication avec le serveur
      - Sauvegarde des connexions au serveur
      - Sauvegarde des messages chiffrés

## Installation
1. Cloner le dépôt:
   Dans un terminal:
     ```git clone https://github.com/Kazulhu/ChatSec/```
3. Pour utiliser en local (sur un seul et même ordinateur):
   - Vous n'avez rien à modifier dans le code ou dans les fichiers.
   - Installer les dépendances:
       Ouvrez un terminal en administrateur dans le dossier du projet:
       ```pip install -r requirements.txt```
4. Pour utiliser sur des appareils différents (serveur sur une VM et client sur différents PC):
   - Vous allez devoir générer de nouveau certificat car les clients vont y accéder d'une adresse IP différentes :
     - Tout d'abord supprimer les deux dossiers CA et CERT
     - Suivez la section 1 de ce github pour installer openssl : https://github.com/MathKode/ServeurSocketTEST/tree/main/SSL1
     - Ensuite effectuer ces étapes depuis un terminal administrateur dans le dossier du projet :
         ```
         mkdir CA
         mkdir CERT
         cd CA
         openssl genrsa -aes256 -out ca-key.pem 4096
         ```
         - Entrez un mot de passe
         - Confirmation du mot de passe
         ```openssl req -new -x509 -sha256 -days 365 -key ca-key.pem -out ca-cert.pem```
         - Entrez le mot de passe
         - Pour les informations seules les deux premières sont nécessaires: Country Name: FR, State: France
         ```
         cd ../CERT
         openssl genrsa -out cert-key.pem 4096
         openssl req -new -sha256 -subj "/CN=SecureCN" -key cert-key.pem -out cert-query.csr
         ```
         - Créer maintenant un fichier extfile.cnf :
           - Ouvrez l'application notepad et écrivez:
             ```subjectAltName=IP:127.0.0.1, IP:<ip-du-serveur-sur-votre-réseau>```
         - Revenez au terminal :
           - ```openssl x509 -req -sha256 -days 365 -in cert-query.csr -CA ../CA/ca-cert.pem -CAkey ../CA/ca-key.pem -out cert-server.pem -extfile extfile.cnf -CAcreateserial```
         - Ouvrez un powershell administrateur (dans le dossier CA):
           ```Import-Certificate -FilePath .\ca-cert.pem -CertStoreLocation Cert:\LocalMachine\Root```
     - Modifier dans le code du client l'adresse ip cible par celle du serveur (que vous avez du mettre dans extfile.cnf)
   
   - Déplacer le dossier Server et CERT ainsi que le fichier requirements.txt sur l'appareil qui hébergera botre serveur (celui possédant l'adresse IP renseigner auparavant)
   - Déplacer le dossier Client et CA ainsi que le fichier requirements.txt sur chaque appareil sur votre réseau utilisant l'application
   - Sur tout les appareils :
     - Ouvrez un terminal en administrateur dans le dossier ou se trouve requirements.txt :
       ```pip install -r requirements.txt```

## Utilisation
1- Assurez vous d'avoir une application d'authentificator d'installer sur votre téléphone, par exemple Authy ou Google Authenticator
2- Lancer le serveur depuis un terminal :
  - Déplacer vous jusqu'à l'emplacement du fichier server.py puis exécutez:
    ```python server.py```
  - Un message précisant l'écoute du serveur devrait apparaitre dans le terminal
3- Lancer l'application depuis un terminal :
  - Déplacer vous jusqu'à l'emplacement du fichier client.py puis exécutez:
    ```python client.py```
  - La fenêtre de l'application devrait apparaitre


## Release Note
**v1.0.1** - 04/07/2024
- Première Release officielle 
- Fonctionnalité basique
- Mise en place de la documentation initiale


