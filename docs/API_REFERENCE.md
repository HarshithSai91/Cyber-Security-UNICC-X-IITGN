# API Reference: Threat Retrieval & Matching Subsystem

The subsystem provides high-performance REST endpoints built with FastAPI.

## Base URL
```
http://localhost:8000
```

---

## 📡 Endpoints

### 1. Match Threat Query
- **Route**: `POST /match` (Aliases: `POST /query`, `POST /api/v1/threats/match`)
- **Content-Type**: `application/json`

#### Request Body
```json
{
  "query": "Attacker exploited CVE-2017-0144 using T1021.002 from host 198.51.100.24",
  "top_k": 5,
  "alpha": 0.5
}
```

#### Parameters
| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `query` | `string` | *(Required)* | Natural language CTI query, IOC list, or incident observation. |
| `top_k` | `integer` | `5` | Maximum number of ranked candidates to return ($1 \le k \le 100$). |
| `alpha` | `float` | `0.5` | Dense vs. sparse weighting factor ($0.0 \le \alpha \le 1.0$). |

#### Response Schema (`200 OK`)
```json
{
  "query_threat_id": "query_1727654321",
  "top_matches": [
    {
      "rank": 1,
      "chunk_id": "446e0fd5adfb0305972d02030e8949fe",
      "composite_score": 0.9625,
      "confidence_tier": "EXACT",
      "evidence_breakdown": {
        "ioc_similarity": 1.0,
        "cve_similarity": 1.0,
        "ttp_similarity": 0.85,
        "semantic_similarity": 0.92
      },
      "attribution": {
        "matching_iocs": ["198.51.100.24"],
        "matching_cves": ["CVE-2017-0144"],
        "shared_malware": ["PsExec"],
        "matching_mitre_techniques": ["T1021.002"]
      },
      "stix_relationships": ["APT29 -[uses]-> T1021.002"],
      "citations": [
        {
          "doc_id": "CVE-2017-0144_EPSS",
          "doc_title": "CVE-2017-0144 Exploit Prediction",
          "source_org": "EPSS",
          "published_date": "2023-01-01T00:00:00Z",
          "page_number": null,
          "text_snippet": "CVE-2017-0144 has an EPSS exploitation probability score of 0.97..."
        }
      ]
    }
  ],
  "pipeline_profile": {
    "exact_match_ms": 0.8,
    "vector_database_ms": 42.1,
    "knowledge_graph_ms": 12.3,
    "scoring_ms": 2.1,
    "citation_ms": 0.6,
    "total_ms": 57.9
  }
}
```

---

## 💻 cURL Example

```bash
curl -X POST "http://localhost:8000/match" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "Apache Log4j remote code execution CVE-2021-44228",
    "top_k": 3
  }'
```
