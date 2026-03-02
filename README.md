
Estrutura de projeto para análise de dados de cibersegurança com camadas bronze/silver/gold, notebooks e módulos Python para ETL, simulação de data warehouse e análises.

### Estrutura

```
s4-cybersecurity-analytics/
├── data/
│   ├── raw/
│   ├── processed/
│   └── gold/
├── notebooks/
│   ├── 01_exploracao_dados.ipynb
│   ├── 02_transformacoes_avancadas.ipynb
│   └── 03_visualizacoes.ipynb
├── src/
│   ├── __init__.py
│   ├── etl_pipeline.py
│   ├── snowflake_simulator.py
│   └── analytics.py
├── requirements.txt
├── README.md
└── .gitignore
```

### Uso

1. Crie um ambiente virtual.
2. Instale as dependências: `pip install -r requirements.txt`.
3. Inicie o Jupyter: `jupyter notebook` e abra os notebooks em `notebooks/`.
4. Coloque arquivos CSV em `data/raw/` para testar a pipeline.

### Módulos

- src/etl_pipeline.py: leitura de CSVs, transformação e geração das camadas processed/gold.
- src/snowflake_simulator.py: simulação simples de tabelas e consultas em memória.
- src/analytics.py: funções de análise e visualização.

