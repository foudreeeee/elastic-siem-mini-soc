# 🛡️ Mini-rapport SOC – Elastic SIEM (Redacted)

## 🧾 Executive Summary

Dans ce projet, j’ai conçu et opéré un mini-SOC basé sur Elastic SIEM afin de reproduire un workflow SOC réaliste.  
J’ai déployé et sécurisé Elasticsearch et Kibana sur Linux, puis intégré des journaux Windows via Winlogbeat.  
Des audits de sécurité avancés ont été configurés pour collecter des événements critiques liés aux processus et à l’authentification.  
L’analyse s’est concentrée sur la détection d’exécutions PowerShell élevées et de scénarios de force brute.  
Les événements ont été corrélés dans le temps afin d’identifier des comportements suspects plutôt que des logs isolés.  
Chaque détection a été évaluée selon son contexte utilisateur, machine et privilèges.  
Le projet inclut une phase de rollback complète pour garantir un retour à un état système sain.  
Ce travail démontre une compréhension pratique des opérations SOC et de la détection orientée comportement.

---

## ✅ Recommendations

- Mettre en place des règles de corrélation automatiques pour prioriser les séquences à haut risque  
- Restreindre et surveiller l’usage de PowerShell via des politiques de sécurité adaptées  
- Implémenter des comptes et rôles dédiés pour les agents SIEM (principe du moindre privilège)  
- Centraliser les logs réseau et Linux afin d’enrichir les corrélations multi-sources  
- Documenter systématiquement les détections et incidents pour améliorer la maturité SOC

Toutes les données sensibles ont été **anonymisées / redacted** afin de rendre ce rapport publiable sur GitHub.

---

## 🎯 Objectifs

- Déployer un SIEM fonctionnel (Elastic Stack)
- Collecter des logs Windows réels
- Comprendre les événements de sécurité (authentification, processus)
- Mettre en place des **détections SOC basées sur le contexte**
- Documenter l’analyse comme dans un environnement professionnel

---

## 🧱 Environnement technique

### Infrastructure
| Système | Rôle |
|------|------|
| Kali Linux | Serveur SIEM (Elasticsearch, Kibana) |
| Windows 11 | Poste surveillé |

### Technologies utilisées
- Elasticsearch
- Kibana
- Winlogbeat
- Elastic Common Schema (ECS)

---

## ⚙️ Installation et mise en place

### 1️⃣ Mise en place du SIEM sur Kali Linux

J’ai installé et configuré **Elasticsearch** et **Kibana** sur Kali Linux en utilisant le dépôt officiel Elastic.

Les points clés de l’installation :
- Activation de la sécurité Elastic (HTTPS + authentification)
- Démarrage et vérification des services
- Connexion sécurisée à Kibana
- Vérification du bon fonctionnement du cluster Elasticsearch

Le SIEM était prêt à recevoir des logs une fois :
- Elasticsearch accessible via HTTPS
- Kibana fonctionnel et authentifié

---

### 2️⃣ Configuration du poste Windows

Sur le poste Windows, j’ai installé **Winlogbeat** afin d’envoyer les journaux de sécurité vers Elasticsearch.

Actions réalisées :
- Installation de Winlogbeat
- Configuration de la sortie Elasticsearch sécurisée
- Installation de Winlogbeat comme **service Windows**
- Vérification de l’envoi des logs dans Kibana

---

### 3️⃣ Activation des audits de sécurité Windows

Afin d’obtenir des logs pertinents pour un SOC, j’ai activé des audits avancés :

- **Création de processus** (Event ID 4688)
- **Journalisation des connexions** (Event ID 4624 / 4625)
- **Journalisation des changements de stratégie d’audit** (Event ID 4719)
- Inclusion de la ligne de commande des processus

Ces configurations permettent de détecter des comportements suspects comme :
- exécutions PowerShell élevées
- tentatives de force brute
- changements de configuration de sécurité

---

## 📥 Données collectées

### Principaux événements observés

| Event ID | Description |
|------|-----------|
| 4719 | Modification de la stratégie d’audit |
| 4688 | Création d’un processus |
| 4625 | Échec d’authentification |
| 4624 | Authentification réussie |

---

## 🕒 Timeline de l’incident (scénario simulé)

### 🟡 Étape 1 – Changement de configuration
- **Event ID 4719**
- Activation de l’audit de création de processus
- Événement critique en SOC (changement de politique de sécurité)

### 🟠 Étape 2 – Exécution PowerShell suspecte
- **Event ID 4688**
- `powershell.exe` lancé depuis `cmd.exe`
- Exécution avec élévation de privilèges
- Outil dual-use, nécessitant une analyse contextuelle

### 🔴 Étape 3 – Tentatives de force brute (scénario)
- Plusieurs **4625** (échecs)
- Suivis d’un **4624** (succès)
- Pattern typique d’une attaque par force brute

---

## 🔎 Logique de détection

### Exemple de règle KQL utilisée

```kql
event.code:4688 and
process.name:"powershell.exe" and
process.parent.name:"cmd.exe" and
winlog.event_data.TokenElevationType:"Type d’élévation de jeton complet (2)"
```

Raisonnement SOC :

- PowerShell est un outil légitime mais souvent utilisé en attaque

- L’élévation de privilèges augmente le niveau de risque

- Le parent cmd.exe est fréquemment observé en post-exploitation

- L’événement isolé est classé suspect, la séquence augmente la sévérité

## 🧠 Méthodologie SOC appliquée

Dans ce projet, j’ai appliqué une méthodologie SOC réaliste :

- Analyse basée sur la corrélation d’événements

- Raisonnement par séquence, pas par log isolé

- Priorisation selon le contexte utilisateur / machine

- Différenciation entre activité légitime et activité suspecte

## 🚨 Évaluation de la sévérité
Scénario	                          |  Sévérité
PowerShell élevé isolé	               Moyenne
PowerShell avec commande encodée	     Élevée
Force brute suivie d’un succès	       Élevée

## 🔄 Nettoyage et remise en état

Après les tests, j’ai effectué un rollback complet :

- Suppression de Winlogbeat

- Désactivation des audits avancés

- Suppression de la journalisation PowerShell

- Désinstallation d’Elasticsearch et Kibana sur Kali

- Cette étape est essentielle pour garantir un environnement propre et maîtrisé.

## 📚 Compétences démontrées

- Déploiement et sécurisation d’un SIEM Elastic

- Collecte et normalisation de logs Windows

- Configuration d’audits de sécurité avancés

- Analyse d’événements Windows (4688, 4719, 4625, 4624)

- Corrélation SOC et raisonnement Blue Team

- Création de règles de détection (KQL)

- Rédaction de rapport SOC professionnel

## 🏁 Conclusion

Ce mini-SOC m’a permis de reproduire un workflow SOC réaliste, depuis l’installation du SIEM jusqu’à l’analyse et la documentation d’événements de sécurité.
Le projet met l’accent sur le raisonnement SOC, la corrélation et la compréhension du contexte, plutôt que sur la simple lecture de logs bruts.
