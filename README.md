## CISA KEV Analytics Dashboard

### Visão Geral
- Dashboard interativo para análise do catálogo CISA Known Exploited Vulnerabilities (KEV).
- Foco em insights acionáveis: fabricantes mais afetados, evolução temporal, risco, ransomware, CWEs, distribuição de CVSS.
- Arquitetura de dados em camadas (Medalhão): Bronze → Silver → Gold, com pipeline ETL automatizado.

### Tecnologias
- Python, Pandas, NumPy, PyArrow/Fastparquet
- Streamlit e Plotly para visualização
- Matplotlib/Seaborn para gráficos adicionais

### Arquitetura de Dados
- Bronze: cópia parquet dos dados brutos.
- Silver: limpeza e enriquecimento (datas, features temporais, classificação de risco, flags, CVSS simulado).
- Gold: agregações de negócio (resumo por fabricante, tendências temporais, top críticas, ransomware, correlação, ranking de CWEs).

### Pré-requisitos
- Windows, macOS ou Linux.
- Python 3.12 ou 3.13.
- Dataset KEV já incluído no repositório em `data/raw/known_exploited_vulnerabilities.csv`. Para atualizar, substitua esse arquivo pelo CSV mais recente da CISA.

### Instalação Rápida (Windows PowerShell)

1) Crie e ative o ambiente virtual:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

2) Instale as dependências:

- Se usar Python 3.13:

```powershell
pip install -r requirements-python313.txt
```

- Se usar Python 3.12 (ou deseja manter versões mais antigas):

```powershell
pip install -r requirements.txt
```

Observação sobre “metadata-generation-failed”:
- Esse erro ocorre ao tentar compilar pacotes como pandas/numpy quando não há wheel compatível para sua versão de Python.
- Em Python 3.13, use o `requirements-python313.txt` (com wheels confirmadas) ou opte por Python 3.12 com o `requirements.txt`.

### Executando o Pipeline ETL
- O dashboard executa o pipeline automaticamente se a Silver não existir.
- Para executar manualmente:

```powershell
python src/etl_pipeline.py
```

Saídas do pipeline:
- Silver: `data/processed/silver_vulnerabilities.parquet`
- Gold: `data/gold/gold_*.csv`

### Executando o Dashboard

```powershell
streamlit run src/dashboard.py
```

- A primeira execução pode disparar o pipeline caso a Silver não exista.
- O dashboard utiliza `src/header_logo_tagline_update.svg` e arquivos Gold (se presentes) para enriquecer a experiência.

### Atualizando o Dataset
- Baixe o CSV mais recente do KEV (CISA) e substitua `data/raw/known_exploited_vulnerabilities.csv`.
- Execute novamente o pipeline (ou apenas reinicie o dashboard e ele rodará o pipeline se necessário).

### Estrutura do Projeto (principal)

```
cybersecurity-analytics/
├─ src/
│  ├─ etl_pipeline.py          # Bronze → Silver → Gold
│  ├─ dashboard.py             # Streamlit
│  ├─ analytics.py             # Relatórios/visuais estratégicos
│  └─ snowflake_simulator.py   # Conceitos Snowflake/Snowpark (simulado)
├─ data/
│  ├─ raw/
│  │  └─ known_exploited_vulnerabilities.csv
│  ├─ processed/
│  │  └─ silver_vulnerabilities.parquet
│  └─ gold/
│     └─ gold_*.csv
├─ requirements.txt
└─ requirements-python313.txt
```

### Comandos Úteis

```powershell
# Ativar venv (Windows)
.\venv\Scripts\Activate.ps1

# Atualizar pip
python -m pip install --upgrade pip

# Rodar ETL
python src/etl_pipeline.py

# Rodar Dashboard
streamlit run src/dashboard.py 
```

### Suporte
- Em caso de problemas de instalação em Windows com Python 3.13, prefira o `requirements-python313.txt`.
- Se persistirem erros de compilação, utilize Python 3.12 com o `requirements.txt`.

