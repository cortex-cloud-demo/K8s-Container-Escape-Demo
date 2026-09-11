# Opening Prompt — Cortex Cloud Demo

> Presentation script for the September 9th workshop.  
> Read aloud before opening the console — sets the context, surfaces the key messages, anchors the narrative.  
> Duration: ~5 min. Tone: calm, factual, not salesy.

---

## Architecture — What Was Deployed

> Read standing up, Flask dashboard open on the **"Code to Cloud to SOC"** tab.

---

A Kubernetes cluster on GCP — GKE.

Inside it, one workload: a Java Spring Boot application, containerized, exposed to the Internet.

The image ships `spring-webmvc 5.3.15` — CVE-2022-22965, Spring4Shell, CVSS 9.8. Remotely exploitable, no authentication required.

The pod is configured the way we regularly see in production environments:
- `privileged: true` — root access to the underlying node
- `hostNetwork: true` — shares the host network namespace
- Kubernetes service account automatically mounted inside the pod
- GKE node with a public IP address

The image was built from this GitHub repo. Every cloud resource is tagged with Yor — `git_commit`, `git_last_modified_by`, `git_repo` — for full traceability back to the developer.

The Cortex agent runs on the GKE node. The XSIAM tenant is connected to the GCP account — CSPM, CWPP, CDR.

```
GitHub repo
  ├── Dockerfile          ← spring-webmvc 5.3.15 (CVE-2022-22965)
  ├── k8s/deployment.yaml ← privileged: true · hostNetwork: true
  └── terraform-infra/    ← GKE · public node IP · Yor git tags

        │  CI: CortexCLI image scan + IaC + SCA
        ▼

GKE Cluster (GCP)
  └── Pod spring-boot  [privileged · hostNetwork · SA token mounted]
        │  Cortex Agent on the node
        ▼

Cortex XSIAM (adeo tenant)
  ├── CSPM / Vuln Policy  → case 230406  (234 posture findings)
  ├── XDR Agent + BIOC    → case 229972  (15 runtime alerts)
  ├── Correlation         → aggregated into 1 single case
  ├── AppSec / CortexCLI  → CI scan · image inventory
  ├── Agentix             → attack path graph · AI recommendations
  ├── Playbooks           → containment · CodeToCloudPivot · AI task
  └── ASM                 → external attack surface exposure
```

> **Say out loud:** "The same platform covers shift-left at build time, continuous cloud posture, runtime process-level detection, AI analysis, and automation. This is not three tools glued together by APIs — it's one agent, one data lake, one console."

---

## Narrative Thread — The 6 Key Messages

> Read or paraphrase before opening the first case. Each key message is the one sentence the audience should walk away with from each segment.

---

### 1 · Posture & Vulnerability — Chris, 20 min

We start from the CDR dashboard — the executive view your cloud security team opens every morning.

We'll drill down into a posture case that groups, on a **single workload**: a critical vulnerability, a Kubernetes misconfiguration, and a confirmed network exposure.

What I want to show is that this is not a list of CVEs.
It's a **contextualized risk**: is this package actually loaded at runtime? Is this pod actually reachable from the Internet? What is the effective privilege level of this identity?

The structure of the case — Issue, Finding, Action — you will see it again, identical, in the next segment on the runtime side. That's intentional.

> **Key message 1:** Prioritization comes from runtime context — the package actually loaded, the workload actually exposed — not from a static CVSS score.

---

### 2 · Runtime CWPP / CDR — Chris, 20 min

On the same workload, we'll see what Cortex detects when the attack actually happens.

Not a flood of alerts — **one single case** that aggregates all runtime events: the Spring4Shell deserialization exploit, the container escape via `nsenter`, the malware deployed on the node, the cluster enumeration using the mounted service account.

And this case is automatically enriched with the posture context we just saw — same model, same console, same timeline.

We'll also watch the playbook fire: automated containment, enrichment, and the cloud-to-code pivot — from the suspicious process all the way to the repo, the Dockerfile, and the responsible commit.

> **Key message 2:** Posture without detection stops at the report. Here, posture and runtime detection share the same platform and the same data lake — that is the structural differentiator against Wiz.

---

### 3 · AppSec / CI Scans — Chris, 20 min

We go back to build time. Why did the image with `spring-webmvc 5.3.15` make it to production?

We'll walk through the GitHub Action pipeline with CortexCLI: image scan, `fail` policy on CVSS ≥ 9, gating at build. This is the ability to **block** — not just alert.

Results land directly in the Cortex platform — no separate Snyk console, no standalone Trivy.

> **Key message 3:** Closed loop — the image blocked in CI is the same identity object as the image observed at runtime in segment 2. One single image inventory, from build to production.

---

### 4 · Agentix — Simon, 20 min

Agentix will visualize the full exploitable chain on this workload: network exposure → vulnerability → identity → reachable data.

This is not a theoretical graph. The recommendations are grounded in the correlated data from both cases — the `privileged` misconfiguration that enabled T1611, the mounted SA token that enabled cluster enumeration.

> **Key message 4:** The AI works on correlated posture + runtime data — which makes its recommendations actionable rather than generic.

---

### 5 · Playbooks & AI Tasks — Simon, 10 min

We'll walk through the remediation orchestration: the playbook triggered from the case, the AI task that analyzes the code-to-cloud card and produces a fixed Dockerfile ready to commit.

> **Key message 5:** This is the same automation engine as XSIAM — not an isolated CNAPP add-on. If you already run XSIAM for your endpoint SOC, this engine is already there for your cloud.

---

### 6 · ASM — Simon, 10 min

We switch to the attacker's perspective: what is actually exposed on the Internet? How does that external service correlate back to the internal asset and its owner?

> **Key message 6:** External attack surface and internal posture in the same inventory — no manual reconciliation, no spreadsheet.

---

## Oral Script — Short Version (read before opening the console)

---

Here's what we set up for today.

A Kubernetes cluster on GCP. A pod running a Spring Boot application vulnerable to Spring4Shell. That pod is running in `privileged` mode, exposed to the Internet, with its Kubernetes service account mounted.

This is a demo environment — but this combination shows up in virtually every cloud audit we run.

We're going to look at this same workload from six angles, with Chris and then Simon.

First, posture — to see how Cortex correlates vulnerability, misconfiguration, and network exposure into a contextualized risk, not a list of CVEs.

Then runtime — to see what happens when the attack actually lands, and how detection enriches and confirms posture in the same console.

Then shift-left — how the image could have been blocked at build.

Then Agentix — the full attack chain visualized end to end, with remediation recommendations grounded in the real data from both cases.

Then playbooks and the AI task — automated response, and a fixed Dockerfile generated in under 30 seconds.

And finally ASM — the attacker's view, what is visible from the Internet, correlated back to the internal asset.

Six angles. One workload. One platform.

*Open the CDR dashboard.*

---

## Client Questions Version

> Ask each question slowly, pause 3 seconds, don't wait for an answer.

---

**"Do you know which Kubernetes workloads are right now vulnerable to a critical CVE, exposed to the Internet, and running in privileged mode — all at the same time?"**

*(3 seconds)*

**"And if you do know — can you tell the difference between a workload that's vulnerable but hasn't been touched yet, and one that's actively being exploited?"**

*(3 seconds)*

**"And when exploitation happens — do your cloud security team and your SOC see the same thing, in the same console, on the same timeline?"**

*(3 seconds)*

**"That's what we're going to show today. Two cases on the same workload. One platform. No manual reconciliation between a posture tool and a detection tool."**

*Open the CDR dashboard.*
