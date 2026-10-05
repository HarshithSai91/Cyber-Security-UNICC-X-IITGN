# Normalized CVE Data Guide

## 1. What we built

We built a lookup and normalization layer that accepts a CVE ID, reads the locally downloaded NVD, CVE List V5, CISA KEV, and EPSS data, and returns one consistent JSON record.

The four source files remain separate. We combine their information only in the output, using the CVE ID as the common key.

**Ultra-simple explanation:** Four people have different facts about the same broken toy. We put all their useful facts on one clean card without throwing away who said what.

## 2. What each source provides

| Dataset | What it mainly provides | Why we use it | Ultra-simple explanation |
|---|---|---|---|
| NVD | Descriptions, NVD status, CVSS scores, CWE weaknesses, CPE applicability, affected products, and references | It provides structured technical analysis and product applicability | "How bad is the broken toy, and which toys are broken?" |
| CVE List V5 | Official CVE identity, CNA/ADP descriptions, publication dates, assigner, affected products, metrics, solutions, workarounds, and references | It preserves information from the organization that created or enriched the CVE record | "Who first told us the toy was broken, and what did they say?" |
| CISA KEV | Confirmed real-world exploitation, date added, remediation deadline, required action, ransomware status, and notes | It tells us whether attackers are known to be using the vulnerability | "Did someone really use the broken part to cause trouble?" |
| EPSS | Exploitation probability, percentile, model version, and score date | It estimates how likely exploitation is in the next 30 days | "What is the chance someone will try the bad trick soon?" |

### CVSS, KEV, and EPSS are different

- **CVSS** describes how damaging and difficult an attack could be.
- **CISA KEV** confirms that attackers have used the vulnerability in the real world.
- **EPSS** predicts the probability of exploitation in the next 30 days.


## 3. Core normalization rules

1. Match all records by `cve_id`.
2. Keep the original datasets unchanged.
3. Convert differently named source fields into one stable structure.
4. Merge only genuine duplicates.
5. Preserve genuine disagreements, such as different CVSS assessments.
6. Keep the source and provider attached to every important fact.
7. Use `null` or an empty list when a value is unavailable; never invent a value.
8. Keep affected and unaffected products distinguishable.
9. Keep the original and cleaned forms of URLs/provider names where useful.
10. Record the source files in `provenance` so every value can be audited.

## 4. Final normalized JSON: section-by-section guide

The examples below use `CVE-2021-23758`.

| Normalized section | What it means | Why it is included | Example | Ultra-simple explanation |
|---|---|---|---|---|
| `cve_id` | Unique vulnerability identifier | It is the join key shared by all four datasets | `CVE-2021-23758` | "The broken toy's name sticker." |
| `available_sources` | Datasets in which this CVE was found | What all sources used | `NVD`, `CVE_LIST_V5`, `CISA_KEV`, `EPSS` | "These are the people who gave us information." |
| `state` | CVE publication state and NVD processing state | It tells whether the CVE is published, rejected, updated, analyzed, or waiting for analysis. | CVE List: `PUBLISHED`; NVD: `Modified` | "Is the card official, and has someone checked or changed it?" |
| `dates` | Reservation, publication, and update timestamps | They support timelines, freshness checks, and incremental processing | Published `2021-12-03`; NVD modified `2026-06-17` | "When was the card made and last changed?" |
| `assigner` | Organization responsible for assigning/reporting the CVE | It establishes ownership and authority | Snyk | "Who first wrote the card?" |
| `title` | Short vulnerability name | It gives the UI and search system a concise label | `Deserialization of Untrusted Data` | "A tiny name for the problem." |
| `descriptions` | All useful descriptions with languages, sources, and providers | Different sources may provide different detail or wording | English and Spanish descriptions from Snyk/NVD plus a CISA explanation | "Different people explain what broke." |
| `affected_products` | Vendors, products, packages, versions, platforms, modules, and aliases | Retrieval needs to answer which software and versions are affected | `AjaxPro.2`, all versions | "Which toys have the bad part?" |
| `cvss_metrics` | Versioned severity assessments with vectors, scores, details, providers, and sources | Risk scoring must preserve different valid assessments | NVD: `9.8 Critical`; Snyk: `8.1 High` | "How big could the ouchie be, according to each doctor?" |
| `ssvc` | Stakeholder-Specific Vulnerability Categorization decisions | It can support operational prioritization when supplied | Empty for this CVE | "What kind of help should happen first?" |
| `weaknesses` | CWE IDs (Common Weakness Enumeration - It is a numbered list of common software-security mistakes.) and human descriptions of the software mistake | They support filtering, grouping, similarity, and explanation. It tells what type of mistake caused the vulnerability. | `CWE-502` | "What kind of mistake made the toy break?" |
| `references` | Deduplicated advisories, patches, reports, and evidence URLs | Investigators and the LLM need verifiable evidence | GitHub patch, Snyk advisory, NVD page | "Where can we check that the story is true?" |
| `cpe_configurations` | Original logical CPE applicability structure | It preserves exact NVD product/version logic, including AND/OR conditions | AjaxPro CPE with an ending version boundary | "The full rule saying exactly which toys count." |
| `cpe_matches` | Simplified searchable CPE entries | Search systems should not have to parse the full nested CPE tree for every query | Vendor `ajaxpro.2 project`, product `ajaxpro.2` | "A shorter toy label that is easy to find." |
| `tags` | Special source labels such as disputed or known exploited | Tags support filtering and exceptional handling | Empty for this record | "Small warning stickers." |
| `known_exploited` | Compact normalized shortcut for confirmed-exploitation information | Applications can access key KEV facts without parsing the full KEV object | Added `2026-08-26`, action due `2026-09-09` | "A quick note saying the bad trick really happened." |
| `cisa_kev` | Full KEV record and catalog-availability flags | It preserves CISA wording, deadlines, ransomware status, notes, and provenance | `listed: true`; ransomware use: `Unknown` | "CISA's complete warning card." |
| `epss` | EPSS availability, score, percentile, model, and score date | Retrieval and prioritization teams can use a time-stamped exploitation prediction | Score `0.89096`; percentile `0.99768` | "The computer guesses an 89-in-100 chance someone tries the bad trick soon." |
| `additional_information` | Solutions, workarounds, exploit notes, timelines, required actions, and other narrative evidence | It retains useful text that does not fit the core tables | CISA required action and notes | "Extra instructions and notes that may help." |
| `provenance` | Source file, schema/model version, and score date | Every normalized value must be traceable to its original evidence | Paths to NVD, CVE List, KEV, and EPSS files | "The receipt showing where every fact came from." |

## 5. Important nested fields

### Affected products

| Field | Meaning | Example | Ultra-simple explanation |
|---|---|---|---|
| `vendor` | Company or project responsible for the product | `Ajax.NET Professional` | "Who made the toy?" |
| `product` | Affected software/product name | `AjaxPro.2` | "Which toy is it?" |
| `versions` | Affected or unaffected release ranges | All versions affected | "Which toy editions are broken?" |
| `status` | Whether the version is affected, unaffected, or unknown | `affected` | "Is this one broken: yes, no, or we do not know?" |
| `cpes` | Standard machine-readable product names | CPE string | "The toy's barcode." |
| `product_aliases` | Alternative names referring to the same product | `AjaxPro.2` | "Other nicknames for the same toy." |
| `sources` / `providers` | Datasets and organizations supporting the claim | NVD, CVE List CNA, Snyk | "Who said this toy is broken?" |

### CVSS metrics

| Field | Meaning | Example | Ultra-simple explanation |
|---|---|---|---|
| `version` | CVSS specification used | `3.1` | "Which measuring ruler was used?" |
| `base_score` | Severity from 0 to 10 | `9.8` | "How big is the ouchie?" |
| `base_severity` | Text category | `CRITICAL` | "Is it tiny, medium, big, or very big?" |
| `vector` | Compact encoding of attack conditions and impact | `AV:N/AC:L/...` | "A tiny secret code describing how the bad thing works." |
| `details` | Expanded vector fields | Network attack, no privileges, no user action | "The secret code written as normal facts." |
| `provider` | Organization that calculated the score | NVD or Snyk | "Which doctor measured the ouchie?" |
| `sources` | Dataset locations containing the assessment | NVD, CVE List CNA | "Which notebooks contain that doctor's number?" |

### EPSS

| Field | Meaning | Example | Ultra-simple explanation |
|---|---|---|---|
| `score` | Predicted probability of exploitation in the next 30 days | `0.89096` = about 89.1% | "About 89 chances out of 100 that someone tries it soon." |
| `percentile` | Relative position among scored CVEs | `0.99768` = higher than about 99.77% | "This one is near the very front of the danger line." |
| `model_version` | Prediction model release | `v2026.06.15` | "Which guessing machine was used?" |
| `score_date` | Time the score was produced | `2026-08-26` | "When did the machine make the guess?" |
| `score_available` | Whether this CVE has an EPSS score | `true` | "Did the machine make a guess for this toy?" |

## 6. Why some information appears more than once

### Multiple descriptions

We retain different languages and materially different descriptions. This helps multilingual search and lets the LLM choose the clearest evidence.

### Multiple affected-product names

Sources may use package names, vendor names, or CPE names for the same product. We merge safe matches and retain aliases when certainty is insufficient.

### Multiple CVSS scores

Different organizations and CVSS versions may produce different valid assessments. We remove exact duplicates but do not erase genuine disagreement.

In the example:

- NVD rates the vulnerability `9.8 Critical`.
- Snyk rates it `8.1 High`.
- An older CVSS 2.0 assessment gives `7.5 High`.

### Both `known_exploited` and `cisa_kev`

- `known_exploited` is a small convenience object for applications.
- `cisa_kev` preserves the complete CISA record.

### Both `cpe_configurations` and `cpe_matches`

- `cpe_configurations` preserves exact logical meaning.
- `cpe_matches` is easier for search and display.

## 7. Missing-data rules

| Situation | Correct interpretation |
|---|---|
| `null` or `[]` | The downloaded sources did not provide a reliable value; it is not a processing failure by itself |
| `cisa_kev.catalog_available: false` | The KEV CSV could not be found |
| `cisa_kev.listed: false` | The CVE is not in the downloaded KEV snapshot; this does **not** prove it has never been exploited |
| `epss.dataset_available: false` | The EPSS CSV could not be found |
| `epss.score_available: false` | No score exists in the downloaded EPSS snapshot; treat this as unknown, never as `0` |
| Multiple different CVSS values | Preserve them with providers because they may be legitimate assessments |
| `NVD: Modified` | The NVD record was updated; it does not mean severity increased |
| Rejected CVE | Retain the record and rejection reason, but do not treat it as a normal active vulnerability |

## 8. Information available but not promoted into primary fields

Some source fields are not useful as top-level investigation data:

- NVD pagination/header fields such as `resultsPerPage`, `startIndex`, and response timestamp are dataset metadata, not CVE facts.
- CVE List `x_legacyV4Record` repeats an older representation of information already available in V5.
- Generator metadata describes which tool produced a source record, not the vulnerability itself.
- Embedded supporting-media payloads are not placed directly in the normalized investigation record.
- Credits are valuable historically but are not required for the current search/investigation MVP.

These omissions keep the interface practical. `provenance` still points to the original files for auditing or later expansion.

## 9. What the next teams should use

| Team/component | Recommended normalized fields |
|---|---|
| Exact retrieval | `cve_id`, `weaknesses`, `cpe_matches`, affected vendor/product/version, tags |
| Semantic/vector retrieval | Title, descriptions, affected products, weakness descriptions, additional information |
| Historical threat matching | CVE, vendor/product/version, CPE, CWE, CVSS attack properties, KEV, EPSS |
| LLM summarization | Descriptions, affected products, metrics, weaknesses, KEV, EPSS, solutions, references |
| Investigator application | Title, status, affected products, highest/all CVSS assessments, KEV, EPSS, evidence links |
| Audit/evaluation | Sources, providers, original URLs, provenance, model/schema versions |

## 10. Thirty-second explanation for a supervisor

> We use the CVE ID to join four complementary cybersecurity sources without modifying them. CVE List provides the official source record, NVD provides structured severity and applicability analysis, CISA KEV confirms real-world exploitation, and EPSS predicts near-term exploitation likelihood. We convert their differently shaped fields into one stable JSON schema, remove only genuine duplicates, preserve disagreements and missing values, and attach provenance to every important fact. This gives the retrieval, LLM, and application teams one auditable interface while keeping the original evidence available.

## 11. The complete example in one simple story

For `CVE-2021-23758`:

- The affected software is AjaxPro.
- The flaw may let an attacker remotely run malicious code.
- NVD rates the possible damage as `9.8/10 Critical`.
- CISA confirms that attackers have exploited it in the real world.
- EPSS estimates approximately an `89.1%` probability of exploitation in the next 30 days.
- The record tells investigators which products are affected, why the software is weak, what action is required, where the evidence came from, and which original files support every fact.

**Ultra-simple story:** This toy has a very bad broken part, someone has already used the broken part to cause trouble, and the computer thinks someone is very likely to try it again soon.
