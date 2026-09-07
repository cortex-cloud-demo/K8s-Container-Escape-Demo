# AI Task — `AIRootCauseAndDevFix`

Copy-paste configuration for the AI prompt task of
`K8s_Container_Escape_CodeToCloud_Pivot_AI.yml`.

The YAML serialization of AI prompt tasks is not published by Palo Alto, so the
node is built once in the playbook editor rather than shipped in the export.
Everything it consumes is already produced by `CodeToCloudPivot` (v1.3.0+).

---

## 1. Add the task

1. Playbook editor → **Task Library** → **AI Prompts**
2. **System** tab → **Local AI Prompt**
   (a playbook-local copy — it will not receive Prompts Library updates, which
   is what you want for a demo that must behave identically every run)
3. Drop it **on the wire between task #2 "Build Investigation Code-to-Cloud
   Card" and task #3 "AI Verdict?"**
4. **Task name**: `AIRootCauseAndDevFix`
   (must start with a letter, no spaces, no special characters)

---

## 2. Inputs → Prompt

```
Tu es analyste SOC senior, spécialiste sécurité des conteneurs et Kubernetes.
Une évasion de conteneur vient d'être détectée en production par Cortex.

CARTE D'INVESTIGATION RUNTIME (Code-to-Cloud) :
[investigation_card]

DOCKERFILE DE L'IMAGE COMPROMISE (chemin [dockerfile_path], commit [commit_sha]).
Les numéros de ligne sont préfixés, ils NE font PAS partie du fichier :
[dockerfile_numbered]

Analyse cette évasion et produis :

1. verdict : true_positive, false_positive ou needs_review, avec un niveau de
   confiance de 0 à 100.
2. severity : Critical, High, Medium ou Low, justifiée par l'exposition réelle
   observée dans la carte (privilèges, runtime conteneur dans la chaîne de
   causalité, exposition réseau du node).
3. executive_summary : un paragraphe destiné au responsable d'incident, sans
   jargon inutile.
4. attack_chain : 3 à 6 étapes ordonnées. Chaque étape porte une technique
   MITRE ATT&CK (identifiant Txxxx + nom officiel).
5. root_cause_in_code : la ou les instructions du Dockerfile qui ont rendu
   l'évasion possible (image de base obsolète ou EOL, absence de directive USER,
   dépôts de paquets périmés, secret ou fichier sensible copié dans l'image,
   binaire de debug embarqué). Pour chacune, cite le numéro de ligne et
   l'instruction exacte, et explique en une phrase pourquoi elle est
   exploitable dans CE scénario précis.
6. fixed_dockerfile : le Dockerfile corrigé, complet, prêt à être commité, qui
   supprime ces causes racines sans casser le fonctionnement de l'application.
   N'inclus AUCUN numéro de ligne dans ce champ.
7. soc_actions : les actions de confinement immédiates, côté SOC.
8. dev_actions : les actions shift-left, côté équipe de développement.
9. blast_radius : ce que l'attaquant peut atteindre depuis le node compromis,
   d'après les seules informations de la carte.

Contraintes : ne fais aucune supposition qui ne soit pas étayée par le contexte
fourni. Si une information manque, dis-le explicitement plutôt que de l'inventer.
```

## 3. Inputs → Extracted Inputs

Bind in the **same order as they appear in the prompt**:

| # | Placeholder           | Bind to (context path)         |
|---|-----------------------|--------------------------------|
| 1 | `investigation_card`  | `${K8sPivot.MarkdownCard}`     |
| 2 | `dockerfile_path`     | `${K8sPivot.DockerfilePath}`   |
| 3 | `commit_sha`          | `${K8sPivot.CommitSHA}`        |
| 4 | `dockerfile_numbered` | `${K8sPivot.DockerfileNumbered}` |

> If `K8sPivot.DockerfileFetchStatus` is not `fetched@<ref>`, the fetch failed
> (private repo → set the `GitHubToken` playbook input) and inputs 2–4 will be
> empty. The prompt still works, it just loses the code channel.

---

## 4. Outputs

- **Context path**: `K8sPivot.AI`
- **Type**: `Unknown`
- **Use structured output**: ON, with this schema
  (top-level `type` must be `object`; allowed nested types are
  `array`, `boolean`, `integer`, `null`, `number`, `object`, `string`)

```json
{
  "type": "object",
  "properties": {
    "verdict": { "type": "string" },
    "severity": { "type": "string" },
    "confidence": { "type": "integer" },
    "executive_summary": { "type": "string" },
    "attack_chain": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "step": { "type": "integer" },
          "description": { "type": "string" },
          "mitre_id": { "type": "string" },
          "mitre_name": { "type": "string" }
        },
        "required": ["step", "description", "mitre_id", "mitre_name"],
        "additionalProperties": false
      }
    },
    "root_cause_in_code": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "line_number": { "type": "integer" },
          "instruction": { "type": "string" },
          "why_vulnerable": { "type": "string" }
        },
        "required": ["line_number", "instruction", "why_vulnerable"],
        "additionalProperties": false
      }
    },
    "fixed_dockerfile": { "type": "string" },
    "soc_actions": { "type": "array", "items": { "type": "string" } },
    "dev_actions": { "type": "array", "items": { "type": "string" } },
    "blast_radius": { "type": "string" }
  },
  "required": [
    "verdict", "severity", "executive_summary", "attack_chain",
    "root_cause_in_code", "fixed_dockerfile", "soc_actions", "dev_actions"
  ],
  "additionalProperties": false
}
```

`verdict` must be one of `true_positive` / `false_positive` / `needs_review` —
task #3 branches on `isEqualString ${K8sPivot.AI.verdict} == true_positive`.
The schema keeps it a plain string because the prompt already constrains the
vocabulary; add an `enum` only if your tenant's schema validator accepts it.

---

## 5. Advanced

| Setting                       | Value | Why |
|-------------------------------|-------|-----|
| **Execution timeout (seconds)** | `300` | **Mandatory.** The default is 10s. A prompt this size returns `504 DEADLINE_EXCEEDED` at 10s — Palo Alto's own docs say to raise it to 120+ for heavy prompts. |
| Extend Issue context          | off   | The structured output already lands on `K8sPivot.AI`. |
| Ignore outputs                | off   | Task #3 reads the verdict. |
| Indicator Extraction mode     | `None` | The card is full of hashes and IPs already extracted by task #1; re-extracting from the AI answer is noise. |
| Mark results as note          | on    | Puts the AI narrative in the war room where the audience sees it. |
| Quiet Mode                    | off   | You *want* the inputs and outputs visible during the demo. |

**On Error**: retries `1`, retry interval `30`.

Model selection (Flash / Thinking / Pro) is only offered in some regions.
Pick **Thinking** or **Pro** if available — the root-cause step is reasoning
work, and Flash tends to give generic Dockerfile advice.

---

## 6. Demo notes

Against the demo image the model should land on, in the Dockerfile:

- the EOL Debian `stretch` repositories pinned to `archive.debian.org`
- the `tomcat:9.x` base image carrying the Spring4Shell-exploitable stack
- the absence of any `USER` directive → the app runs as root, which is what
  turns a webshell into a node-level escape
- `COPY flag /flag` → sensitive material baked into the layer

The screen moment: `K8sPivot.AI.fixed_dockerfile` next to the original, in the
same issue that fired thirty seconds earlier.

**Wiring the loop further** — once the GitHub integration is configured, add a
task after #4 that opens a pull request carrying `${K8sPivot.AI.fixed_dockerfile}`
against `${inputs.RepoURL}`. The runtime alert then closes on a merged fix, not
on a ticket.
