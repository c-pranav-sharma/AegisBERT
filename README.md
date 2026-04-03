# 🛡️ AegisBERT: Zero-Day Threat Intel Engine
**A Transformer-based Semantic Classifier for Automated Vulnerability Triaging**

---

## 📑 Project Overview
**AegisBERT** is an enterprise-grade cybersecurity asset designed to solve the "Triage Bottleneck" in Security Operations Centers (SOC). Traditional security tools rely on signature-based detection (matching specific strings), which fails against **Zero-Day exploits** or complex technical narratives where the signature is unknown.

AegisBERT utilizes **ModernBERT**, a state-of-the-art encoder-only transformer, fine-tuned on a massive corpus of technical security data. It understands the *semantic intent* of an attack, allowing it to classify raw logs, source code, and forensic reports into 13 high-impact threat categories with sub-200ms latency.

---

## 🧠 Core Innovation: Why ModernBERT?
Standard BERT (2018) is limited by architectural constraints that make it inefficient for modern forensic analysis. AegisBERT utilizes **ModernBERT (2024/25)** to leverage three critical advancements:

1. **8,192 Token Context Window:** Traditional encoders truncate at 512 tokens. AegisBERT can ingest entire C++ source files or 20-page incident reports in a single pass without losing critical "root cause" evidence.
2. **Flash Attention:** Implements hardware-aware attention mechanisms that reduce computational complexity from $O(N^2)$ to $O(N \log N)$, enabling 3x faster inference on standard CPUs.
3. **Rotary Positional Embeddings (RoPE):** Enhances the model's ability to understand the relative distance between technical tokens (like variable names and function calls) in long code blocks.



---

## 🛠️ Technology Stack
| Layer | Technology | Purpose |
| :--- | :--- | :--- |
| **Model** | **ModernBERT-Base** | Encoder-only Transformer for NLU (Natural Language Understanding). |
| **ML Framework** | **PyTorch & Transformers** | Deep learning backend and model weight management. |
| **Backend API** | **FastAPI** | High-performance, asynchronous REST interface. |
| **Frontend UI** | **Streamlit** | Interactive dashboard for security analyst interaction. |
| **Orchestration** | **Docker & Docker Compose** | Microservice containerization and deployment. |
| **Visualization** | **Plotly** | Real-time rendering of Softmax probability distributions. |

---

## 🧪 Hugging Face Fine-Tuning Lifecycle
The model was fine-tuned using the **Hugging Face Trainer API** to transform a general-purpose language model into a cybersecurity domain expert.

### **1. Dataset Composition**
The training set consisted of **150,000+ technical entries** curated from:
- **NVD (National Vulnerability Database):** Raw CVE descriptions.
- **CISA KEV:** Known Exploited Vulnerabilities narratives.
- **Exploit-DB:** Raw proof-of-concept code snippets.

### **2. Training Hyperparameters**
- **Optimizer:** AdamW with Weight Decay ($1e-2$).
- **Learning Rate:** $5e-5$ with a Linear Decay Scheduler.
- **Batch Size:** 32 (optimized for memory efficiency).
- **Epochs:** 5 (ensuring convergence without overfitting).
- **Loss Function:** Categorical Cross-Entropy.

---

## 📊 Confidence Levels & Softmax Logic
AegisBERT provides a "Calibrated Confidence" score. The raw output (logits) from the 13-class classification head is passed through a **Softmax layer** to produce a probability distribution:

$$P(y_i | X) = \frac{e^{z_i}}{\sum_{j=1}^{13} e^{z_j}}$$

- **Model Confidence:** The resulting percentage (e.g., 99.8%) represents the model's certainty.
- **Triage Logic:** If the top confidence is below **65%**, the engine flags the input as "Low Confidence - Manual Review Required" to prevent automated triage errors.

---

## 📋 Threat Classification Mapping
The engine maps forensic inputs to the following 13 classes, tiered by operational risk:

| Class | Risk Level | Description |
| :--- | :--- | :--- |
| **RCE / CMD_INJECTION** | **CRITICAL** | Remote execution or shell hijacking attempts. |
| **B_OVERFLOW** | **CRITICAL** | Memory corruption and stack smashing signatures. |
| **SQLI / SSRF** | **HIGH** | Database exfiltration or cloud metadata theft. |
| **XSS / PATH_TRAVERSAL** | **MEDIUM** | Client-side injection or local file inclusion. |
| **AUTH_FAILURE / DOS** | **MEDIUM** | Brute force or resource exhaustion. |
| **INFO_DISC / CSRF** | **LOW** | Accidental data leaks or session hijacking. |
| **OTHER** | **INFO** | Baseline logs or non-malicious technical text. |

---

## 🚀 Setup & Deployment
### **1. Local Environment**
AegisBERT is fully containerized. Ensure you have Docker and Docker Compose installed.

### **2. Model Weights (Manual Step)**
Due to GitHub's file size restrictions, the fine-tuned weights are stored externally:
- **Download Weights:** `[INSERT_YOUR_DRIVE_LINK_HERE]`
- **Place in Folder:** Extract weights into the `./model` directory so that `config.json` is at the root of the folder.

### **3. Initialization**
```bash
# Build and start the microservices
docker compose up --build
