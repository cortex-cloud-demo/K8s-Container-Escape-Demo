# Script démo — Cortex Cloud | 2h live workshop

**Format** : Workshop / Demo live — pas de deck. Dashboard Flask sur `http://localhost:5555` + console Cortex XSIAM.  
**Scénario** : Spring4Shell (CVE-2022-22965) sur un pod GKE (GCP) — container escape via `nsenter` → vol de credentials IMDS → cluster takeover.  
**Speakers** : Chris (segments 1–3) · Simon (segments 4–6)  
**Console** : [https://adeo.xdr.eu.paloaltonetworks.com](https://adeo.xdr.eu.paloaltonetworks.com)

---

## Cases réels à présenter

| Case | ID | Lien direct | Type | Severity | Score |
|------|----|-------------|------|----------|-------|
| Posture | **230406** | [ouvrir](https://adeo.xdr.eu.paloaltonetworks.com/incident-view?caseId=230406) | DOMAIN_POSTURE | **Critical** | 83/100 |
| Runtime | **229972** | [ouvrir](https://adeo.xdr.eu.paloaltonetworks.com/incident-view?caseId=229972) | DOMAIN_SECURITY | **High** | 70/100 |

---

## Checklist pré-démo (J-1)

```
[ ] Dashboard lancé      : cd dashboard && ./run.sh  →  http://localhost:5555
[ ] Case 230406 ouvert   : posture, critique, GKE — vérifier qu'il est toujours "new"
[ ] Case 229972 ouvert   : runtime, high, 15 alerts — vérifier que le playbook est déclenché
[ ] Playbooks déployés   : CORTEX > Deploy All Scripts + Deploy All Playbooks
[ ] Scans CI exécutés    : AppSec > Scan Image + Terraform + SCA
[ ] Agentix              : graph d'attaque pré-généré sur le workload GKE
[ ] ASM                  : profil d'exposition externe ouvert sur CVE-2022-22965
```

**Onglets navigateur à avoir ouverts dans l'ordre :**

| # | Onglet | Contenu |
|---|--------|---------|
| 1 | Cortex → CDR Dashboard | Vue Executive |
| 2 | Cortex → Cases → **230406** | Posture — CVE + misconfigs GKE |
| 3 | Cortex → Cases → **229972** | Runtime — 15 alerts, nsenter, malware |
| 4 | Dashboard Flask | Onglet Cloud / Runtime |
| 5 | Cortex → AppSec | Résultats dernier scan CI |
| 6 | Cortex → Agentix | Graph pré-généré |
| 7 | Cortex → ASM | Exposition externe CVE-2022-22965 |

---

## 1 — Chris | 20 min | Posture & Vulnerability : du risque théorique au risque priorisé

### Ouverture depuis le dashboard CDR (2 min)

> "On va commencer là où votre équipe cloud security commence chaque matin — le dashboard CDR."

**Action** : Cortex → CDR Dashboard (vue Executive).

Montrer les métriques en haut de page : assets critiques exposés, issues actives, tendance 7 jours.

> "Ce n'est pas un tableau de bord de conformité. Chaque chiffre est pondéré par le contexte runtime — accessibilité réseau réelle, privilèges effectifs, criticité de l'asset. On y revient."

---

### Drill-down sur le case posture 230406 (6 min)

**Action** : Ouvrir le case **230406** — `https://adeo.xdr.eu.paloaltonetworks.com/incident-view?caseId=230406`

Ce case regroupe **234 alerts** sur un seul workload GKE, corrélées automatiquement :

**Workload ciblé** : `gke-gke-escape-demo-k8s-escape-demo-n-ad0b1c52-h4q7` (GKE node pool)  
**Sources** : Cloud Network Analyzer · Compute Policy · CSPM Scanner · Vulnerability Policy · Attack Path

> "234 findings, 4 catégories de risque — ATTACK_PATH, CONFIGURATION, POSTURE, VULNERABILITY — sur **le même workload**, regroupés automatiquement en un seul case. Score de risque : 83/100, severity Critical."

**Trois signaux clés à montrer :**

#### Signal 1 — Exposition réseau (Cloud Network Analyzer)

| Alert | Severity | Description |
|-------|----------|-------------|
| Google Compute Engine instance exposed to the public internet | HIGH | Node GKE `gke-gke-escape-demo-k8s-escape-demo-n-21827800-38ld` joignable depuis Internet |
| GCE with web server ports exposed to the public internet | HIGH | Ports HTTP/HTTPS ouverts sur ce même node |

> "Cortex Network Analyzer a scanné la topologie réseau GCP et identifié que ce node est directement accessible depuis Internet. Ce n'est pas une règle de compliance — c'est une observation de l'accessibilité réelle."

#### Signal 2 — Vulnérabilités critiques (Vulnerability Policy)

| CVE | Package | Version | Severity |
|-----|---------|---------|----------|
| **CVE-2022-22965** (Spring4Shell) | `spring-webmvc` | 5.3.15 | **CRITICAL** |
| **CVE-2022-22965** | `spring-web` | 5.3.15 | **CRITICAL** |
| **CVE-2022-22965** | `spring-core` | 5.3.15 | **CRITICAL** |
| **CVE-2022-22965** | `spring-beans` | 5.3.15 | **CRITICAL** |
| **CVE-2025-24813** | `tomcat-embed-core` | 9.0.56 | **CRITICAL** |
| **CVE-2023-44487** (HTTP/2 Rapid Reset) | `tomcat-embed-core` | 9.0.56 | **CRITICAL** |
| **CVE-2020-1938** (Ghostcat) | `tomcat-util` | 9.0.21 | **CRITICAL** |

> "On ne parle pas d'une CVE — on a **4 packages Spring vulnérables à Spring4Shell** sur le même node, plus Ghostcat et HTTP/2 Rapid Reset sur Tomcat. Et Cortex sait que ces packages sont **réellement chargés au runtime**, pas juste présents dans le filesystem."

#### Signal 3 — Misconfigurations Kubernetes (Compute Policy)

| Finding | Severity |
|---------|----------|
| Minimize the admission of **privileged containers** | **CRITICAL** |
| Service Account Tokens mounted unnecessarily | **CRITICAL** |
| Containers sharing the **host network namespace** | **CRITICAL** |
| Multiple Docker daemon security misconfigurations | **CRITICAL** |
| Secure Boot for Shielded GKE Nodes not enabled | MEDIUM |
| Private Nodes not enabled (public IP on nodes) | MEDIUM |

> "Le pod tourne en mode `privileged`, partage le namespace réseau de l'hôte, et monte le service account token. C'est exactement la combinaison qui rend possible l'escape via `nsenter` — on va le voir en direct dans 10 minutes."

---

### Structure Issue / Finding / Action (4 min)

**Action** : Dans le case 230406, dérouler la hiérarchie `Issue > Findings > Actions recommandées`.

> "Retenez cette structure — vous allez la retrouver à l'identique au point 2, côté runtime. Même console, même hiérarchie, même timeline. C'est intentionnel."

Actions suggérées à montrer :
- Patch Spring Boot → `spring-webmvc 5.3.15 → 5.3.18+` — lien direct vers le commit dans le repo (via tag Yor `git_commit`)
- Supprimer `privileged: true` dans `k8s/deployment.yaml` → diff proposé
- Activer Shielded GKE Nodes + Private Nodes → action automatisable via playbook

> "L'action n'est pas 'ouvrez un ticket'. C'est 'voilà le fichier à modifier, voilà le commit, voilà la PR à ouvrir'."

---

### Message clé posture (3 min)

**Action** : Montrer le filtre "Package loaded at runtime" vs "Package present".

> "Wiz et Lacework vous donnent une liste de CVE. Cortex vous donne **les CVE qui comptent aujourd'hui**, parce qu'on corrèle la posture avec ce qu'on observe réellement en runtime. Sur ce workload : 4 packages Spring4Shell réellement chargés, node réellement exposé sur Internet, pod en mode privileged. Sans ce contexte, vous noyez votre équipe dans 234 findings dont la majorité est théorique."

**Différenciateurs :**
- Agent Cortex = télémétrie runtime → le package est-il réellement chargé ?
- Tags Yor sur l'infra Terraform → quel commit, quel dev, quel repo a créé ce pod ?
- Score de risque composé = CVE × exposition réseau × privilèges IAM (83/100 sur ce case)

---

### Transition (1 min)

> "On a vu le risque théorique priorisé. Maintenant je montre ce que Cortex voit quand l'attaque se produit réellement sur ce même workload."

**Action** : Basculer sur le dashboard Flask → onglet **Cloud / Runtime Security**.

---

## 2 — Chris | 20 min | Runtime CWPP / CDR : détection temps réel

### Déclenchement ou présentation de l'attaque (3 min)

**Action** : Dashboard Flask → **Run Full Demo** (si live) ou directement ouvrir le case **229972**.

> "L'attaque en 5 étapes : Spring4Shell RCE sur le pod, `nsenter` pour l'escape vers le node GKE, vol des credentials IMDS (`169.254.169.254`), kubectl depuis l'intérieur du pod pour énumérer le cluster, et déploiement d'un malware WildFire. Regardez ce que Cortex a vu."

---

### Agrégation en case unique — case 229972 (5 min)

**Action** : Cortex Cases → ouvrir le case **229972**.

Ce case agrège **15 alerts** en un seul incident :

> "15 findings, 4 catégories d'attaque — Privilege Escalation, Malware, Exploit, Execution — **un seul case**. Pas 15 tickets. MITRE ATT&CK : 6 tactiques, 8 techniques mappées automatiquement."

**Timeline des 15 alerts à dérouler :**

| Count | Alert | Severity | Source | MITRE |
|-------|-------|----------|--------|-------|
| 6× | **Suspicious Input Deserialization** | MEDIUM | XDR Agent | — (Spring4Shell RCE) |
| 6× | **Local Analysis Malware** | MEDIUM | XDR Agent | — (`/tmp/wildfire-test` ELF détecté) |
| 1× | **Kubernetes nsenter container escape** | MEDIUM | XDR Analytics BIOC | T1611 — Escape to Host |
| 1× | **Container Image immutability compromised** | HIGH | Correlation | T1017 — Application Deployment Software |
| 1× | **Kubectl-Based Cluster Enumeration Attempt** | HIGH | Correlation | T1015 / TA0008 — Lateral Movement |

> "Regardez le détail de l'alert `nsenter` : la commande capturée est `nsenter --target 1 --mount --uts --ipc --net --pid -- curl -s -X PUT -H X-aws-ec2-metadata-token-ttl-seconds: 21600 http://169.254.169.254/latest/api/token`. En clair : l'attaquant a échappé du conteneur et a immédiatement interrogé le service IMDS pour voler les credentials cloud. Cortex l'a capturé avec la commande exacte."

> "Et regardez l'enrichissement automatique : Cortex a déjà fait le lien entre ce node GKE et le case posture 230406 — même workload, même console, même structure Issue/Finding/Action."

**Node compromis** : `gke-gke-escape-demo-k8s-escape-demo-n-0a6bf236-cdfp`  
**MITRE Tactics détectées** : TA0002 Execution · TA0003 Persistence · TA0004 Privilege Escalation · TA0007 Discovery · TA0008 Lateral Movement · TA0043 Reconnaissance

---

### Playbook : réponse automatisée (5 min)

**Action** : Dans le case 229972 → onglet Playbook → montrer `K8s_Container_Escape_Spring4Shell_Containment` déclenché.

Étapes à commenter en live :

| Tâche | Ce qu'elle fait |
|-------|-----------------|
| `ExtractK8sContainerEscapeIOCs` | Extraction IOCs : hash ELF `wildfire-test`, IP IMDS, SA token utilisé |
| `K8sSearchSimilarEvents` | Threat hunting : autres pods avec `nsenter` ou `wildfire-test` sur le cluster ? |
| `InvokeK8sContainmentLambda` | Lambda isole le pod via API GKE (STS auth) — pas de kubectl côté SOC |
| `K8sForensicAnalysis` | Dump forensique du pod avant suppression |
| `EnrichCloudAssetYorTags` | Enrichissement git → qui a déployé ce pod, quel commit, quel repo |

> "Le containment est automatisé. Le pod est isolé en moins de 30 secondes. L'analyste n'a pas à toucher kubectl — il valide et le playbook exécute."

---

### Pivot Cloud-to-Code (5 min)

**Action** : Dans le case 229972 → War Room → entrée `CodeToCloudPivot`.

Carte d'investigation générée automatiquement :
- **Image** : `chrisley75/k8s-escape-demo-vuln-app` (version détectée au runtime)
- **Node** : `gke-gke-escape-demo-k8s-escape-demo-n-0a6bf236-cdfp`
- **Dockerfile path** : `Dockerfile` → commit SHA → lien GitHub direct
- **Lignes coupables identifiées** :
  - `FROM tomcat:9-jre8` — Tomcat 9.0.21/9.0.56 portant CVE-2020-1938, CVE-2023-44487, CVE-2025-24813
  - `spring-webmvc 5.3.15` dans `pom.xml` → Spring4Shell (CVE-2022-22965)
  - Absence de `USER` → tourne en root → `nsenter` possible

> "En un clic, on est passé du process `nsenter` capturé en production jusqu'au **commit GitHub** qui a introduit la vulnérabilité. Le dev reçoit une PR avec le Dockerfile corrigé — pas un ticket Jira vague."

---

### Message clé runtime — différenciateur vs Wiz (2 min)

> "Wiz vous donnerait le case posture 230406 — excellent. Mais quand l'attaque se produit sur le case 229972, Wiz ne voit rien. Ici, la détection runtime et la posture partagent **le même data lake, la même console, la même timeline**. L'analyste SOC n'a pas à jongler entre deux outils pour comprendre ce qui s'est passé."

---

## 3 — Chris | 20 min | AppSec / CI Scans : prévention au build

### Principe : boucle fermée (2 min)

> "On vient de voir l'attaque réussir. La question est : pourquoi l'image avec `spring-webmvc 5.3.15` est arrivée en production sans être bloquée ?"

**Action** : Dashboard Flask → onglet **AppSec** (cyan).

---

### GitHub Action : scan et gating (6 min)

**Action** : Montrer `.github/workflows/` → pipeline CI avec CortexCLI.

Policy configurée dans Cortex :
- CVSS ≥ 9 → **`FAIL`** — le build bloque (Shift-Left)
- CVSS 7-8 → **`WARN`** — alerte dans la plateforme

**Action** : Bouton **Scan Image** → résultats réels sur l'image du demo :

| Finding | Package | Severity | Statut |
|---------|---------|----------|--------|
| CVE-2022-22965 (Spring4Shell) | `spring-webmvc 5.3.15` | CVSS 9.8 | **FAIL** |
| CVE-2022-22965 | `spring-web 5.3.15` | CVSS 9.8 | **FAIL** |
| CVE-2025-24813 | `tomcat-embed-core 9.0.56` | CRITICAL | **FAIL** |
| CVE-2020-1938 (Ghostcat) | `tomcat-util 9.0.21` | CRITICAL | **FAIL** |
| Secret baked : `flag` copié dans l'image | — | HIGH | **FAIL** |

**Action** : Bouton **Terraform** → résultats IaC :

| Finding | Fichier | Statut |
|---------|---------|--------|
| `privileged: true` | `k8s/deployment.yaml` | **FAIL** |
| `hostNetwork: true` | `k8s/deployment.yaml` | **FAIL** |
| `automountServiceAccountToken: true` | `k8s/service-account.yaml` | **FAIL** |

**Action** : Bouton **SCA** → `app/pom.xml` → `spring-webmvc 5.3.15` → CVE-2022-22965 identifiée dans les dépendances Maven.

> "Si ces policies avaient été actives, l'image ne serait jamais partie en registry. Les cases 230406 et 229972 n'existeraient pas."

---

### Module AppSec dans la plateforme (4 min)

**Action** : Cortex → AppSec → résultats du dernier scan CI.

> "Les résultats du scan CI sont dans la même plateforme — pas de console Snyk, pas de Trivy séparé."

Points à montrer :
- Inventaire d'images : l'image `vuln-app` apparaît ici **ET** dans l'inventaire runtime — même SHA, même identité
- Lien entre le finding CI (CVE dans `pom.xml`) et le case 229972 (container escape) → **même objet image**

---

### Message clé AppSec — un seul inventaire (4 min)

> "L'image bloquée en CI est le même objet que l'image observée en runtime. Si elle passe quand même en prod, vous le voyez immédiatement — avec le diff entre ce qui était dans le scan CI et ce qu'on observe en runtime."

**Différenciateur** : Aqua Security et Prisma Cloud (ancienne génération) ont des consoles AppSec et Runtime séparées. Ici c'est un seul inventaire du build à la prod.

**Action** : Onglet **Security Radar** → spider chart avant/après activation des scans CI.

---

### Transition (2 min)

> "Simon va maintenant montrer comment Cortex analyse le **chemin d'attaque complet** avec Agentix — de l'exposition externe jusqu'à la donnée impactée."

---

## 4 — Simon | 20 min | Agentix : analyse de chemin d'attaque

### Graph d'attaque — visualisation (7 min)

**Action** : Cortex → Agentix → graph d'attaque sur le workload GKE.

> "Agentix ne raisonne pas sur un finding isolé. Il raisonne sur le **graphe complet** ancré dans les données réelles des cases 230406 et 229972."

Parcourir le graph nœud par nœud :

```
Internet
  → GCE node exposé publiquement (Cloud Network Analyzer — case 230406)
  → Pod spring-boot  [spring-webmvc 5.3.15 = CVE-2022-22965 | privileged | hostNetwork]
  → Escape via nsenter (T1611 — capturé dans case 229972)
  → IMDS 169.254.169.254 → credentials cloud volés
  → kubectl depuis le pod → énumération cluster (Lateral Movement — case 229972)
  → Secrets K8s tous namespaces
  → Données cloud accessibles avec credentials IMDS
```

> "Ce chemin de 5 sauts, de l'exposition réseau jusqu'aux données cloud, est documenté dans vos deux cases. Agentix l'assemble et le visualise."

---

### Recommandations Agentix — raisonnement exposé (8 min)

**Action** : Ouvrir les recommandations Agentix sur ce chemin.

| Recommandation | Raisonnement exposé |
|----------------|---------------------|
| Patcher `spring-webmvc` → 5.3.18+ | "CVE-2022-22965 est le vecteur initial confirmé (case 229972 — Suspicious Input Deserialization × 6)" |
| Supprimer `privileged: true` | "Sans ce flag, T1611 nsenter ne fonctionne pas — l'escape est bloqué même si le RCE réussit (case 230406)" |
| Activer Private Nodes GKE | "Le node est joignable depuis Internet — supprimer l'IP publique coupe le premier maillon (case 230406)" |
| Bloquer l'accès IMDS depuis les pods | "La commande nsenter capturée interroge directement 169.254.169.254 — restreindre via metadata-concealment addon GKE" |
| Réduire les permissions du SA | "Le SA token monté (case 230406) a permis l'énumération cluster (case 229972 — Kubectl-Based Cluster Enumeration)" |

> "Ce qui est différent ici : chaque recommandation est justifiée par les données de **vos propres cases** — pas des bonnes pratiques génériques. L'IA travaille sur les mêmes events que votre SOC."

---

### Message clé Agentix (5 min)

> "Un graph d'attaque sans données runtime, c'est de la théorie. Agentix travaille sur les mêmes events que le SOC — la même télémétrie agent. La recommandation 'supprimer privileged' est justifiée par le fait que T1611 nsenter a réellement été exécuté sur ce node, pas par une règle de compliance."

**Comparer avec Wiz Attack Paths** : Wiz génère des chemins basés sur la posture statique. Agentix intègre ce que l'agent a observé en runtime — `nsenter` réellement exécuté, `wildfire-test` réellement déployé, IMDS réellement interrogé.

---

## 5 — Simon | 10 min | Playbooks & tâches IA

### Orchestration depuis le case 229972 (4 min)

**Action** : Case **229972** → onglet Playbook → `K8s_Container_Escape_CodeToCloud_Pivot_AI`.

> "Le playbook se déclenche automatiquement. Chaque tâche est visible en temps réel — pas une boîte noire."

Étapes clés :
1. **CodeToCloudPivot** → carte d'investigation : image, Dockerfile, commit SHA du node `gke-gke-escape-demo-k8s-escape-demo-n-0a6bf236-cdfp`
2. **AIRootCauseAndDevFix** → tâche IA : analyse la carte, produit verdict + severity + chaîne MITRE + Dockerfile corrigé

**Action** : War Room → entrée IA avec le Dockerfile corrigé.

---

### Tâche IA — le moment écran (4 min)

**Action** : Afficher côte à côte le `Dockerfile` original vs le `fixed_dockerfile` produit par l'IA.

```dockerfile
# ORIGINAL — ce qui a tourné en production (capturé dans le case 229972)
FROM tomcat:9-jre8           # tomcat-util 9.0.21 : CVE-2020-1938 (Ghostcat) + CVE-2023-44487
                             # Pas de USER → root → nsenter possible (T1611 confirmé)
COPY flag /flag              # Données sensibles baked dans l'image
# spring-webmvc 5.3.15 dans pom.xml → CVE-2022-22965 (Suspicious Input Deserialization × 6)
```

```dockerfile
# CORRIGÉ — produit par la tâche IA sur la base des deux cases
FROM tomcat:10-jre17-temurin   # Élimine CVE-2020-1938, CVE-2023-44487, CVE-2025-24813
RUN groupadd -r appuser && useradd -r -g appuser appuser
USER appuser                   # nsenter T1611 non applicable sans root
# flag retiré — ne pas bake des données sensibles dans l'image
# spring-webmvc → 5.3.18+ dans pom.xml (CVE-2022-22965 patchée)
```

> "L'IA a identifié les lignes coupables en citant les CVEs réelles du case 230406 et les techniques MITRE capturées dans le case 229972. Le Dockerfile corrigé est prêt à committer."

---

### Message clé — même moteur que XSIAM (2 min)

> "Ce moteur de playbooks, c'est XSIAM. Pas un add-on CNAPP isolé. Si vous avez déjà XSIAM pour votre SOC endpoint, vous avez déjà ce moteur pour votre cloud. Vous n'achetez pas un deuxième orchestrateur."

---

## 6 — Simon | 10 min | ASM : exposition & vulnérabilité

### Vue attaquant — ce qui est réellement exposé (5 min)

**Action** : Cortex → ASM → vue d'exposition externe.

> "On change de perspective : on se met à la place de l'attaquant. Qu'est-ce qui est visible depuis Internet ?"

Points à montrer :
- Node GKE `gke-gke-escape-demo-k8s-escape-demo-n-21827800-38ld` → IP publique → port HTTP détecté
- **Corrélation automatique** : ce service externe est lié à l'asset interne dans le case 230406 (même finding Cloud Network Analyzer)
- **Propriétaire identifié** via tags Yor : `git_last_modified_by = cley@paloaltonetworks.com`, `git_repo = K8s-Container-Escape-Demo`

> "L'ASM a scanné Internet, a trouvé ce service Spring Boot exposé, et l'a automatiquement corrélé avec le case posture 230406 — sans réconciliation manuelle."

---

### Corrélation CVE-2022-22965 sur surface externe (4 min)

**Action** : Filtrer ASM sur `CVE-2022-22965` → l'asset exposé remonte.

> "C'est la CVE exploitée dans le case 229972 — Suspicious Input Deserialization × 6. Un attaquant qui scanne Internet peut identifier cette application comme vulnérable à Spring4Shell **avant même d'avoir un accès**. C'est exactement le scénario du case 229972."

| Approche concurrente | Approche Cortex |
|----------------------|-----------------|
| Surface externe dans un outil tiers (Censys, Shodan, etc.) | Surface externe dans le **même inventaire** que les cases 230406 et 229972 |
| Réconciliation manuelle pour faire le lien | Lien automatique : même node, même CVE, même case |
| Propriétaire inconnu | Propriétaire identifié via tags Yor sur l'infra GKE |

---

### Message clé ASM (1 min)

> "La surface externe et la posture interne dans le même inventaire. Quand un attaquant trouve quelque chose sur Internet, vous le voyez dans le même écran que le case 230406 qui documente le risque interne. Pas de réconciliation, pas de tableur."

---

## Synthèse finale (5 min optionnels)

> "Ce qu'on vient de faire en 2 heures : on a suivi le **même workload compromis** — le node GKE `gke-gke-escape-demo` — à travers 6 angles. Le case 230406 documente le risque posture (234 findings). Le case 229972 documente l'attaque réelle (15 alerts, 5 étapes, 6 tactiques MITRE). Dans Cortex, c'est le même data lake, la même console."

| Capacité | Wiz | Lacework | Cortex Cloud |
|----------|:---:|:--------:|:------------:|
| Posture cloud CSPM (case 230406) | ✓ | ✓ | ✓ |
| Détection runtime K8s (case 229972) | ✗ | Partiel | ✓ (agent natif) |
| CVE contextualisées runtime (package loaded) | ✗ | Partiel | ✓ |
| nsenter / container escape détecté (T1611) | ✗ | ✗ | ✓ |
| Commande IMDS capturée en temps réel | ✗ | ✗ | ✓ |
| Playbooks automatisés (même moteur XSIAM) | ✗ | ✗ | ✓ |
| Pivot code-to-cloud (Dockerfile + commit) | ✗ | ✗ | ✓ |
| ASM dans le même inventaire | Partiel | ✗ | ✓ |
| IA sur données posture + runtime corrélées | ✗ | ✗ | ✓ (Agentix) |

---

## Notes de régie — risques à anticiper

| Risque | Vérification avant démo | Fallback |
|--------|--------------------------|----------|
| Case 230406 ou 229972 fermé / résolu | Vérifier statut "new" via API ou console | Rouvrir le case + screenshot de secours |
| Lambda containment KO | `aws sts get-caller-identity` dans le terminal Flask | Montrer le log de la dernière exécution |
| Case posture sans findings CVE | Forcer `Scan All` depuis AppSec la veille | Screenshot des 234 alerts en backup |
| Agentix timeout (2-3 min à générer) | Pré-générer le graph avant la session | Screenshot du graph en backup |
| MITRE heatmap SOC Live vide | Vérifier connexion Cortex API (CORTEX > Configure) | Basculer directement sur le case 229972 |
| Tags Yor manquants → pivot code-to-cloud KO | Vérifier intégration GitHub dans Cortex | Montrer les tags dans `terraform-infra/terraform.tfstate` |
| Playbook non déclenché sur le case | Déclencher manuellement depuis War Room | Ouvrir `K8s_Container_Escape_Spring4Shell_Containment` → Run |
