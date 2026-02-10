# Argos-Recon

Scanner de reconnaissance de vulnérabilités léger, asynchrone et orienté "Playbooks".

## Installation

1. Pré-requis : Python 3.9+
2. Installation des dépendances :
   ```bash
   pip install -r requirements.txt

   ## Sécurité & Avertissement

⚠️ **Usage Autorisé Uniquement**
Cet outil est un scanner de reconnaissance active. Il est conçu pour auditer des cibles potentiellement vulnérables ou mal configurées.

**Choix d'Architecture Intentionnels :**
- **Validation SSL Désactivée (`ssl.CERT_NONE`, `verify=False`)** : Le scanner accepte volontairement les certificats expirés, auto-signés ou invalides afin de pouvoir analyser les cibles en défaut de configuration TLS. **Ne pas utiliser ce code pour des transactions sécurisées.**
- **Fuzzing Léger** : Le module `probes` teste des URLs communes (robots.txt, wp-login.php, etc.).
- **User-Agent** : Les requêtes utilisent l'User-Agent par défaut de `httpx` (ou configuré dans le code), ce qui est visible dans les logs serveur.

Utilisez cet outil uniquement sur des périmètres dont vous êtes propriétaire ou pour lesquels vous disposez d'un mandat explicite.