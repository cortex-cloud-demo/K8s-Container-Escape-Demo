# Prompt d'ouverture — Cortex Cloud demo

> Script de présentation pour le workshop du 9 septembre.  
> A lire à voix haute avant d'ouvrir la console — pose le contexte, annonce les messages clés, ancre la narration.  
> Durée : ~5 min. Ton : calme, pédagogique, pas commercial.

---

## Rappel architecture — ce qui a été déployé

> Lire debout, dashboard Flask ouvert sur le tab **"Code to Cloud to SOC"**.

---

Un cluster Kubernetes sur GCP — GKE.

Dedans, un workload : une application Java Spring Boot, containerisée, exposée sur Internet.

L'image embarque `spring-webmvc 5.3.15` — CVE-2022-22965, Spring4Shell, CVSS 9.8. Remotement exploitable, sans authentification.

Le pod est configuré volontairement de la façon qu'on retrouve régulièrement en production :
- `privileged: true` — accès root au node sous-jacent
- `hostNetwork: true` — namespace réseau de l'hôte partagé
- Service account Kubernetes monté dans le pod
- Node GKE avec IP publique

L'image a été buildée depuis ce repo GitHub. Chaque ressource cloud est taguée avec Yor — `git_commit`, `git_last_modified_by`, `git_repo`.

L'agent Cortex tourne sur le node. Le tenant XSIAM est connecté au compte GCP — CSPM, CWPP, CDR.

```
GitHub repo
  ├── Dockerfile          ← spring-webmvc 5.3.15 (CVE-2022-22965)
  ├── k8s/deployment.yaml ← privileged: true · hostNetwork: true
  └── terraform-infra/    ← GKE · node IP publique · tags Yor git

        │  CI : CortexCLI scan image + IaC + SCA
        ▼

GKE Cluster (GCP)
  └── Pod spring-boot [privileged · hostNetwork · SA token monté]
        │  Cortex Agent sur le node
        ▼

Cortex XSIAM (tenant adeo)
  ├── CSPM / Vuln Policy  → case 230406  (234 findings posture)
  ├── XDR Agent + BIOC    → case 229972  (15 alerts runtime)
  ├── Correlation         → agrégation en 1 case unique
  ├── AppSec / CortexCLI  → scan CI · inventaire images
  ├── Agentix             → graph d'attaque · recommandations IA
  ├── Playbooks           → containment · CodeToCloudPivot · AI task
  └── ASM                 → surface d'exposition externe
```

> **À verbaliser :** "La même plateforme couvre le shift-left au build, la posture cloud, la détection runtime au niveau process, l'analyse IA et l'automatisation. Ce n'est pas trois outils intégrés par API — c'est un seul agent, un seul data lake, une seule console."

---

## Fil narratif — les 6 messages clés

> Lire ou paraphraser avant d'ouvrir le premier case. Chaque message clé est la phrase à retenir en sortant de chaque segment.

---

### 1 · Posture & Vulnerability — Chris, 20 min

On va commencer par le dashboard CDR — c'est la vue executive que votre équipe cloud security consulte chaque matin.

On va descendre dans un case posture qui regroupe sur un **seul workload** : une vulnérabilité critique, une misconfiguration Kubernetes, et une exposition réseau confirmée.

Ce que je veux montrer, c'est que ce n'est pas une liste de CVE.
C'est un risque **contextualisé** : ce package est-il réellement chargé en runtime ? Ce pod est-il réellement joignable depuis Internet ? Quel est le niveau de privilège réel de cette identité ?

La structure du case — Issue, Finding, Action — vous allez la revoir à l'identique au segment suivant, côté runtime. C'est intentionnel.

> **Message clé 1 :** La priorisation vient du contexte runtime — le package réellement chargé, le workload réellement exposé — pas d'un score CVSS statique.

---

### 2 · Runtime CWPP / CDR — Chris, 20 min

Sur le même workload, on va voir ce que Cortex détecte quand l'attaque se produit réellement.

Pas une pluie d'alertes — **un case unique** qui agrège tous les événements runtime : la désérialisation Spring4Shell, le container escape via `nsenter`, le malware déployé sur le node, l'énumération du cluster avec le service account.

Et ce case est enrichi automatiquement par le contexte posture qu'on vient de voir — même modèle, même console, même timeline.

On va aussi voir le playbook se déclencher : containment automatique, enrichissement, et le pivot cloud-to-code — du process suspect jusqu'au repo, au Dockerfile, au commit responsable.

> **Message clé 2 :** La posture sans détection s'arrête au rapport. Ici, posture et détection runtime partagent la même plateforme et le même data lake — c'est le différenciateur structurel face à Wiz.

---

### 3 · AppSec / CI Scans — Chris, 20 min

On remonte au build. Pourquoi l'image avec `spring-webmvc 5.3.15` est-elle arrivée en production ?

On va voir le pipeline GitHub Action avec CortexCLI : scan de l'image, policy `fail` sur CVSS ≥ 9, gating au build. C'est la capacité de **bloquer** — pas juste d'alerter.

Les résultats sont visibles directement dans la plateforme Cortex — pas de console Snyk, pas de Trivy séparé.

> **Message clé 3 :** Boucle fermée — l'image bloquée en CI est le même objet d'identité que l'image observée en runtime au segment 2. Un seul inventaire d'images, du build à la prod.

---

### 4 · Agentix — Simon, 20 min

Agentix va visualiser la chaîne exploitable de bout en bout sur ce workload : exposition réseau → vulnérabilité → identité → donnée accessible.

Ce n'est pas un graph théorique. Les recommandations sont justifiées par les données corrélées des deux cases — la misconfiguration `privileged` qui a rendu T1611 possible, le SA token monté qui a permis l'énumération cluster.

> **Message clé 4 :** L'IA travaille sur la donnée corrélée posture + runtime — ce qui rend ses recommandations actionnables plutôt que génériques.

---

### 5 · Playbooks & tâches IA — Simon, 10 min

On va voir l'orchestration de la remédiation : le playbook déclenché depuis le case, la tâche IA qui analyse la carte code-to-cloud et produit le Dockerfile corrigé.

> **Message clé 5 :** C'est le même moteur d'automatisation que XSIAM — pas un add-on CNAPP isolé. Si vous avez déjà XSIAM pour votre SOC endpoint, ce moteur est déjà là pour votre cloud.

---

### 6 · ASM — Simon, 10 min

On va se mettre à la place de l'attaquant : qu'est-ce qui est réellement exposé sur Internet ? Comment ce service externe se corrèle-t-il avec l'asset interne et son propriétaire ?

> **Message clé 6 :** La surface d'exposition externe et la posture interne dans le même inventaire — pas de réconciliation manuelle, pas de tableur.

---

## Script oral — version courte (à lire avant d'ouvrir la console)

---

Voici ce qu'on a mis en place pour aujourd'hui.

Un cluster Kubernetes sur GCP. Un pod qui fait tourner une application Spring Boot vulnérable à Spring4Shell. Ce pod est en mode `privileged`, exposé sur Internet, avec son service account Kubernetes monté.

C'est un environnement de démonstration — mais cette combinaison, on la retrouve dans la quasi-totalité des audits cloud qu'on conduit.

On va parcourir six angles sur ce même workload, avec Chris puis Simon.

Posture d'abord — pour comprendre comment Cortex corrèle vulnérabilité, misconfiguration et exposition en un risque contextualisé, pas une liste de CVE.

Runtime ensuite — pour voir ce que ça donne quand l'attaque se produit réellement, et comment la détection vient confirmer et enrichir la posture, dans la même console.

Puis le shift-left — comment on aurait pu bloquer l'image au build.

Puis Agentix — la chaîne d'attaque visualisée de bout en bout, avec les recommandations de remédiation fondées sur les données réelles des deux cases.

Puis les playbooks et la tâche IA — la réponse automatisée, le Dockerfile corrigé généré en 30 secondes.

Et enfin l'ASM — la vue attaquant, ce qui est visible depuis Internet, corrélé avec l'asset interne.

Six angles. Un seul workload. Une seule plateforme.

*Ouvrir le dashboard CDR.*

---

## Version "questions au client"

> Poser chaque question lentement, marquer une pause de 3 secondes.

---

**"Est-ce que vous savez quels workloads Kubernetes sont en ce moment vulnérables à une CVE critique, exposés sur Internet, et configurés en mode privileged — simultanément ?"**

*(3 secondes)*

**"Et si vous le savez — est-ce que vous faites la différence entre un workload vulnérable qui n'a pas encore été touché, et un workload qui est en train d'être exploité ?"**

*(3 secondes)*

**"Et quand l'exploitation se produit — est-ce que votre équipe cloud security et votre SOC voient la même chose, dans la même console, sur la même timeline ?"**

*(3 secondes)*

**"C'est ce qu'on va montrer aujourd'hui. Deux cases sur le même workload. Même plateforme. Pas de réconciliation manuelle entre un outil posture et un outil detection."**

*Ouvrir le dashboard CDR.*
