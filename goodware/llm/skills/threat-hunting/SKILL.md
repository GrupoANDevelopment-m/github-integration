# Threat Hunting Skill

Modo operacional para procurar proactivamente ameaças no sistema.

## Workflow

1. **Collect**: Listar todas as ameaças activas e recentes
2. **Correlate**: Cruzamento com IOCs conhecidos (data/iocs.json)
3. **Map**: Identificar técnicas MITRE ATT&CK associadas
4. **Hunt**: Sugerir queries OSQuery-like para procura adicional
5. **Report**: Sumário com findings + acções recomendadas

## Tools usadas

- `list_active_threats(severity_min="high")`
- `search_iocs(value, type)`
- `lookup_cve(query)`
- `run_yara_scan(path)`

## Output esperado

```json
{
  "active_threats": [...],
  "ioc_matches": [...],
  "mitre_techniques": [...],
  "suggested_hunts": [...],
  "priority_actions": [...]
}
```
