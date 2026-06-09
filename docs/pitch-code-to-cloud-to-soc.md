---
marp: true
theme: default
class: invert
paginate: true
size: 16:9
header: 'Cortex Cloud — Code to Cloud to SOC'
footer: 'Palo Alto Networks · Partner enablement'
style: |
  section {
    background: linear-gradient(135deg, #0a0e1a 0%, #1a1f2e 100%);
    color: #e8eaed;
    font-family: 'Inter', 'Helvetica Neue', sans-serif;
  }
  h1 { color: #ff6b1a; font-size: 2.2em; }
  h2 { color: #ff8c42; border-bottom: 2px solid #ff6b1a; padding-bottom: 0.3em; }
  h3 { color: #ffb380; }
  strong { color: #ffd699; }
  table { font-size: 0.85em; }
  th { background: #ff6b1a; color: #0a0e1a; }
  code { background: #1f2937; color: #ff8c42; padding: 0.1em 0.4em; border-radius: 3px; }
  blockquote { border-left: 4px solid #ff6b1a; color: #cbd5e1; font-size: 1.1em; }
  .columns { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; }
  .columns3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 1rem; }
  .kpi { font-size: 3em; color: #ff6b1a; font-weight: 700; line-height: 1; }
  .kpi-label { font-size: 0.9em; color: #cbd5e1; }
  .center { text-align: center; }
---

<!--
==================================================================
HOW TO EXPORT
==================================================================
Install Marp CLI once:
  npm install -g @marp-team/marp-cli

Export to PowerPoint (.pptx):
  marp docs/pitch-code-to-cloud-to-soc.md --pptx -o docs/pitch.pptx

Export to PDF:
  marp docs/pitch-code-to-cloud-to-soc.md --pdf -o docs/pitch.pdf

Export to HTML (standalone, navigable in browser):
  marp docs/pitch-code-to-cloud-to-soc.md --html -o docs/pitch.html

Google Slides:
  1. Generate .pptx (command above)
  2. Upload to Google Drive
  3. Right-click → Open with → Google Slides → File → Save as Google Slides

Speaker notes (FR script in HTML comments) are preserved in the .pptx
export and visible in PowerPoint's "Notes" pane.
==================================================================
-->

# **From Code to Cloud to SOC**
## See the attack. Stop the breach. Automatically.

A live demonstration of how **Cortex Cloud** detects and contains
a cloud-native attack — **end to end, in under a minute**.

---
*Palo Alto Networks · Partner enablement · 10-15 min*

<!--
SCRIPT FR (1 min) :
"Bonjour à tous. Aujourd'hui, je vais vous montrer comment Cortex Cloud
permet à vos clients de voir une attaque cloud-native se dérouler en
temps réel, et surtout — c'est ça le point clé — de la stopper
automatiquement, sans intervention humaine, en moins d'une minute.
Cette démo, vous allez pouvoir la rejouer chez vos clients en 15 minutes
chrono. C'est un outil commercial puissant."
-->

---

## **The cloud risk is exploding**

<div class="columns3">

<div class="center">
<div class="kpi">+95%</div>
<div class="kpi-label">of organizations<br>experienced a<br>cloud security incident</div>
</div>

<div class="center">
<div class="kpi">277</div>
<div class="kpi-label">days average<br>to detect and<br>contain a breach</div>
</div>

<div class="center">
<div class="kpi">$4.9M</div>
<div class="kpi-label">average cost<br>of a cloud<br>data breach</div>
</div>

</div>

> **The attack surface has moved.** Workloads, identities, configurations, secrets — all in the cloud, all interconnected, all exploitable.

<!--
SCRIPT FR (1 min30) :
"Les chiffres parlent d'eux-mêmes. 95% des organisations ont subi un
incident cloud sur les 12 derniers mois. Le temps moyen pour détecter
ET contenir une brèche reste de 277 jours — neuf mois. Et le coût
moyen d'une brèche cloud atteint 4,9 millions de dollars.
La réalité : l'attaque ne vient plus du périmètre. Elle vient de
l'intérieur — d'une mauvaise config, d'une identité compromise,
d'un container qui s'échappe. Vos clients le savent. Ils cherchent
une réponse."
-->

---

## **Why customers can't test their own defenses**

<div class="columns">

### ❌ **It's hard**
- Building a realistic attack scenario requires **deep offensive skills**
- Most security teams are **defenders**, not red teamers
- Engaging a pentest firm = **weeks of planning, $$$**

### ❌ **It's risky**
- Testing in production = **business disruption**
- Building a lab from scratch = **months of effort**
- Tools are **fragmented** across CSPM, CWPP, XDR, SOAR…

</div>

> **Result:** customers buy security tools but **never validate** they actually detect and stop an attack — until it's too late.

<!--
SCRIPT FR (2 min) :
"Voilà le vrai problème de vos clients : ils achètent des outils de
sécurité, mais ils ne testent jamais s'ils marchent vraiment.
Pourquoi ? Parce que c'est dur — il faut des compétences offensives
que les équipes défensives n'ont pas. Parce que c'est risqué — on ne
joue pas une attaque en prod. Parce que monter un lab prend des mois.
Et parce qu'avec 5 ou 6 outils empilés, personne ne sait qui détecte
quoi. Conclusion : ils découvrent que leur stack ne marche pas... le
jour de la vraie attaque. C'est exactement ce que Cortex Cloud résout."
-->

---

## **The Cortex Cloud answer — one platform, three moments**

<div class="columns3">

### 🛡️ **Before**
**Shift-Left**
Find vulnerabilities and misconfigurations **in the code**, before they reach production.

### ⚡ **During**
**Runtime Protection**
See and stop attacks **as they happen**, on every workload, every identity, every cloud.

### 🤖 **After**
**Automated Response**
Contain, investigate and remediate **without human intervention** — in seconds.

</div>

> **The unique value:** the same platform sees the code, the cloud, and the SOC. **No silo. No blind spot. No swivel-chair.**

<!--
SCRIPT FR (1 min30) :
"Cortex Cloud, c'est trois moments, une seule plateforme.
Avant l'attaque : on trouve les vulnérabilités dans le code, avant qu'elles
n'arrivent en prod. C'est le shift-left.
Pendant l'attaque : on voit ce qui se passe en temps réel, sur chaque
workload, chaque identité, chaque cloud.
Après — ou plutôt PENDANT, parce qu'on parle de quelques secondes : on
contient et on remédie automatiquement.
La différence avec la concurrence : un seul agent, une seule console,
une seule donnée partagée entre les trois moments. Pas de silo."
-->

---

## **The demo — what your customer will see**

<div class="columns">

### 🎬 **A realistic attack chain**
- Starts from a **vulnerable web app** in production
- Progresses to **container escape**
- Ends with **full cluster takeover** and data theft
- ~ **2 minutes**, fully reproducible

### 🎯 **The platform reaction**
- **Real-time alerts** with full context
- **Automatic correlation** across code + cloud + endpoint
- **Playbooks fire** without analyst input
- **Workload contained** in seconds

</div>

> **One click in the dashboard → the attack runs → Cortex Cloud reacts → the customer sees the full story.**

<!--
SCRIPT FR (1 min30) :
"La démo en elle-même : on lance une attaque réaliste — pas un truc
artificiel, un scénario que vos clients vivent vraiment — qui part
d'une appli web vulnérable, qui s'échappe du conteneur, qui prend
le contrôle du cluster. En face, Cortex Cloud réagit en temps réel :
alertes contextualisées, corrélation automatique entre les couches,
playbooks qui se déclenchent seuls, et workload coupé en quelques
secondes. Tout ça en un clic dans le dashboard. C'est le 'wow moment'."
-->

---

## **Detection — Cortex Cloud sees everything**

<div class="columns">

### **Full visibility across the kill chain**
- **Code** vulnerabilities flagged before deployment
- **Misconfigurations** detected in cloud posture
- **Runtime behavior** monitored on every workload
- **Identity abuse** tracked across cloud accounts
- **Lateral movement** mapped in real time

### **Unified telemetry**
- Single console, single timeline
- Native **MITRE ATT&CK** mapping
- Auto-correlation across cloud, container, identity, endpoint

</div>

> **The analyst doesn't hunt for evidence — Cortex delivers the full incident story, already assembled.**

<!--
SCRIPT FR (2 min) :
"Côté détection, Cortex Cloud voit toute la chaîne d'attaque, pas
juste un bout. Les vulnérabilités côté code, les mauvaises configs
côté cloud, le comportement runtime sur chaque workload, l'abus
d'identité entre comptes AWS, et le mouvement latéral en temps réel.
Tout converge dans une seule console, avec une seule timeline, mappée
nativement sur MITRE ATT&CK. Le résultat : l'analyste ne perd plus
des heures à reconstituer ce qui s'est passé. Cortex lui livre
l'histoire complète, déjà assemblée. C'est ça qui change la vie d'un
SOC."
-->

---

## **Response — Cortex Cloud acts, automatically**

<div class="columns">

### **From alert to containment, hands-off**
1. **Detection** → multi-source correlation
2. **Enrichment** → forensic context auto-gathered
3. **Decision** → playbook applies policy
4. **Action** → workload contained, identity revoked, ticket opened

### **What gets remediated automatically**
- Compromised workload isolated
- Malicious process killed
- Stolen tokens rotated
- Vulnerable image blocked from redeploy

</div>

<div class="columns3">

<div class="center">
<div class="kpi">< 60s</div>
<div class="kpi-label">MTTR<br>(automated)</div>
</div>

<div class="center">
<div class="kpi">0</div>
<div class="kpi-label">analyst clicks<br>required</div>
</div>

<div class="center">
<div class="kpi">24/7</div>
<div class="kpi-label">consistent<br>response</div>
</div>

</div>

<!--
SCRIPT FR (2 min) :
"Et c'est là le vrai différentiateur de Cortex Cloud : on ne se contente
pas de détecter, on RÉPOND. Automatiquement. Le workflow : détection
multi-source, enrichissement forensique automatique, décision via
playbook, action immédiate. Le workload compromis est isolé, le process
malicieux tué, les tokens volés révoqués, l'image vulnérable bloquée
au redéploiement. Tout ça en moins de 60 secondes, sans intervention
humaine, 24/7, de manière 100% reproductible. Comparez ça aux 277 jours
de moyenne du marché. Le ROI est immédiat."
-->

---

## **Before / After — the customer outcome**

| | **Before Cortex Cloud** | **After Cortex Cloud** |
|---|---|---|
| **Vulnerabilities** | Discovered in production | Caught **before** deployment |
| **Attack visibility** | Fragmented across 5+ tools | **Single pane**, full context |
| **Detection time** | Hours to days | **Seconds** |
| **Response** | Manual, inconsistent | **Automated**, 24/7 |
| **MTTR** | Days | **Under 1 minute** |
| **Compliance** | Annual audit panic | **Continuous** posture |
| **Team workload** | Alert fatigue | Focused on real threats |

> **The shift:** from *reactive* and *manual* to *proactive* and *autonomous*.

<!--
SCRIPT FR (1 min30) :
"Ce tableau est celui que vous devez laisser à votre interlocuteur.
Avant Cortex : vulnérabilités en prod, visibilité fragmentée, détection
en heures ou jours, réponse manuelle, MTTR en jours, compliance en mode
panique annuelle, équipes saturées d'alertes.
Après Cortex : tout est inversé. Détection en secondes, réponse
automatisée, MTTR en moins d'une minute, posture continue.
Le message à retenir : on passe d'une sécurité réactive et manuelle
à une sécurité proactive et autonome. C'est la promesse, et c'est
exactement ce que la démo prouve."
-->

---

## **Why this matters for you, our partners**

<div class="columns">

### 💼 **A repeatable sales asset**
- **One-click demo** at every customer meeting
- **15 minutes** to deliver the wow moment
- Works on **any Kubernetes** (AWS, on-prem, customer's own)
- Zero install required at the customer

### 🚀 **A platform story that wins**
- Competitors show **one layer** — we show the **full chain**
- Justifies the **CNAPP + XDR + SOAR** consolidation
- Opens the door to **larger deals** and **strategic accounts**

</div>

> **You don't sell a tool. You sell an outcome — and you can prove it in 15 minutes.**

<!--
SCRIPT FR (1 min30) :
"Pourquoi cette démo est un game-changer pour vous :
Côté commercial — c'est un asset rejouable en un clic chez n'importe
quel client, en 15 minutes, sur n'importe quel Kubernetes. Pas
d'installation, pas de prérequis lourds.
Côté stratégique — vos concurrents montrent une seule couche, vous
montrez toute la chaîne. C'est ce qui justifie la consolidation
CNAPP + XDR + SOAR, c'est ce qui ouvre les gros deals, c'est ce qui
vous différencie.
Le message : vous ne vendez plus un outil, vous vendez un résultat —
et vous pouvez le prouver en 15 minutes devant le client."
-->

---

## **Next steps**

<div class="columns">

### 📅 **Book a customer POV**
- **1-2 hours** of customer time
- We provide the environment
- Output: live demo + tailored report

### 🤝 **Enable your team**
- Train your pre-sales on the demo flow
- Provide co-selling support
- Access to the **partner enablement repo**

</div>

### 📚 **Resources available today**
- Demo video, architecture diagrams, pitch deck
- Step-by-step partner guide
- Contact your **Palo Alto channel SE** to get started

<!--
SCRIPT FR (1 min) :
"Les prochaines étapes, très concrètement :
Pour un POV client : on a besoin d'une à deux heures de leur temps,
on fournit l'environnement, et le client repart avec une démo live
et un rapport personnalisé sur sa posture.
Pour votre équipe : on forme vos pré-sales sur le flow de démo,
on vous accompagne en co-selling, et on vous donne accès au repo
d'enablement partenaire.
Toutes les ressources sont prêtes — vidéo, architecture, ce deck,
guide pas-à-pas. Contactez votre channel SE Palo Alto et on lance."
-->

---

# **Questions ?**

## Let's turn cloud risk into competitive advantage.

**Contact:** _your Palo Alto channel SE_
**Resources:** Partner enablement portal

<!--
SCRIPT FR — anticipez ces questions Q&A :

1. "Combien de temps pour déployer chez un client ?"
   → Environnement de démo prêt en 20-30 min. POV avec données client :
     1 à 2 jours selon scope.

2. "Sur quels clouds ça marche ?"
   → AWS, GCP, Azure, et n'importe quel Kubernetes (on-prem inclus).
     La démo couvre AWS et on-prem aujourd'hui.

3. "Quelle différence vs Wiz, CrowdStrike, Sysdig ?"
   → Wiz : posture cloud uniquement, pas de runtime ni de SOC.
   → CrowdStrike : excellent endpoint, faible côté cloud-native.
   → Sysdig : runtime correct, pas de plateforme SOC unifiée.
   → Cortex Cloud : la seule plateforme qui couvre code + cloud + SOC
     avec un seul agent et une seule donnée.

4. "Le client doit avoir tout l'écosystème Cortex pour en bénéficier ?"
   → Non. On peut commencer par une brique (CNAPP ou XDR) et étendre.
     Mais la vraie valeur — la chaîne complète — vient de la plateforme
     unifiée. C'est l'objectif de l'upsell.

5. "Quel est le pricing ?"
   → Modèle par workload + endpoint. Renvoyez vers votre channel manager
     pour un devis personnalisé.

6. "Combien de temps pour qu'un client soit autonome dessus ?"
   → Onboarding standard : 2 à 4 semaines avec accompagnement Pro Services
     ou partenaire certifié.
-->
