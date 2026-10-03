# Goodware v3.0 — Machine Learning Models

**Data**: 2026-10-03
**Total de modelos treinados**: 4 (2 RandomForest + 2 IsolationForest)
**Melhor accuracy**: 96.00% (UNSW-NB15)

---

## Modelos em Produção

### 1. `threat_predictor_unsw_nb15.joblib` (PRINCIPAL)

**Modelo principal usado em produção.**

| Métrica | Valor |
|---------|------:|
| Algorithm | RandomForestClassifier |
| n_estimators | 100 |
| max_depth | 20 |
| n_jobs | -1 (all cores) |
| random_state | 42 |
| Dataset | UNSW-NB15 (175,341 records) |
| Features | 45 |
| Train rows | 140,272 |
| Test rows | 35,069 |
| **Train accuracy** | **98.81%** |
| **Test accuracy** | **96.00%** |
| Tamanho | 40.39 MB |

#### Métricas Detalhadas

```
              precision    recall  f1-score   support
      normal       0.95      0.92      0.94     11200
      attack       0.96      0.98      0.97     23869
    accuracy                           0.96     35069
   macro avg       0.96      0.95      0.95     35069
weighted avg       0.96      0.96      0.96     35069
```

#### Class Balance
- Normal: 56,000 (32%)
- Attack: 119,341 (68%)

### 2. `threat_predictor_nsl_kdd.joblib`

**Modelo secundário (validação histórica).**

| Métrica | Valor |
|---------|------:|
| Algorithm | RandomForestClassifier |
| Dataset | NSL-KDD (148,555 records) |
| Features | 41 |
| **Test accuracy** | **77.66%** |
| Tamanho | 7.37 MB |

### 3. `anomaly_detector_unsw_nb15.joblib`

**Detecção de anomalias (out-of-distribution).**

| Métrica | Valor |
|---------|------:|
| Algorithm | IsolationForest |
| n_estimators | 100 |
| contamination | 0.3 |
| Dataset | UNSW-NB15 |

### 4. `anomaly_detector_nsl_kdd.joblib`

**Anomaly detector para NSL-KDD.**

---

## Treino

### Datasets usados

```
data/nsl_kdd/KDDTrain+.txt    125,973 rows
data/nsl_kdd/KDDTest+.txt      22,544 rows
data/unsw_nb15/UNSW_NB15.csv  175,341 rows (cleaned)
```

### Pipelines

- `goodware/prediction/training/train_nsl_kdd.py`
- `goodware/prediction/training/train_unsw_nb15.py`

### Reproduzir treino

```bash
# NSL-KDD
PYTHONPATH=. LD_LIBRARY_PATH=./vendor/oqs/lib \
  python3 -m goodware.prediction.training.train_nsl_kdd

# UNSW-NB15
PYTHONPATH=. LD_LIBRARY_PATH=./vendor/oqs/lib \
  python3 -m goodware.prediction.training.train_unsw_nb15
```

### Tempo de treino

| Dataset | Hardware | Tempo |
|---------|----------|------:|
| NSL-KDD | CPU only | ~3 min |
| UNSW-NB15 | CPU only | ~30 sec |

---

## Uso via API

```bash
# Predict
curl -X POST http://127.0.0.1:8444/api/predict \
  -H 'Content-Type: application/json' \
  -d '{
    "features": {
      "dur": 0.5, "proto": "tcp", "service": "-",
      "state": "FIN", "spkts": 6, "dpkts": 4,
      "sbytes": 258, "dbytes": 172
    }
  }'

# Status
curl http://127.0.0.1:8444/api/predictor/status
```

---

## Métricas Detalhadas dos Modelos

Ver `models/training_metadata_*.json`:

- `models/training_metadata_nsl_kdd.json`
- `models/training_metadata_unsw_nb15.json`

---

## Roadmap ML

- [ ] v3.1 — Deep learning (Transformer-based) para zero-day
- [ ] v3.2 — Ensemble de múltiplos modelos
- [ ] v3.3 — Online learning (incremental)
- [ ] v3.4 — Explicabilidade (SHAP values)
