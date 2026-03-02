"""
Pipeline ETL para análise de cibersegurança
Arquitetura: Bronze → Silver → Gold
Dados públicos: OWASP Top 10 / CISA KEV
"""

import pandas as pd
import numpy as np
import requests
import os
from datetime import datetime
import json
from pathlib import Path

class SecurityAnalyticsETL:
    """
    Pipeline completo com arquitetura medalhão
    Demonstra Pandas avançado + conceitos Snowflake
    """
    
    def __init__(self, raw_data_path="data/raw", processed_path="data/processed", gold_path="data/gold"):
        self.raw_path = Path(raw_data_path)
        self.processed_path = Path(processed_path)
        self.gold_path = Path(gold_path)
        
        # Criar diretórios se não existirem
        for path in [self.raw_path, self.processed_path, self.gold_path]:
            path.mkdir(parents=True, exist_ok=True)
        
        self.bronze_df = None
        self.silver_df = None
        self.gold_dfs = {}
    
    def extract_from_cisa(self):
        """
        Extrai dados da CISA Known Exploited Vulnerabilities (API pública)
        Fonte: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
        """
        print("📥 Extraindo dados da CISA KEV...")
        
        # URL da API pública da CISA
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        
        try:
            response = requests.get(url)
            response.raise_for_status()
            data = response.json()
            
            # Converter para DataFrame
            df = pd.DataFrame(data['vulnerabilities'])
            
            # Adicionar metadados
            df['data_extracao'] = datetime.now()
            df['fonte'] = 'CISA KEV'
            
            # Salvar camada BRONZE (dados brutos)
            bronze_path = self.raw_path / f"cisa_kev_{datetime.now().strftime('%Y%m%d')}.parquet"
            df.to_parquet(bronze_path, index=False)
            
            self.bronze_df = df
            print(f"   ✅ Extraídos {len(df)} registros")
            print(f"   💾 Salvos em: {bronze_path}")
            
            return df
            
        except Exception as e:
            print(f"   ❌ Erro na extração: {e}")
            # Fallback: dados simulados para demonstração
            return self._generate_sample_data()
    
    def _generate_sample_data(self):
        """
        Gera dados simulados para demonstração (caso a API falhe)
        """
        print("   ⚠️ Usando dados simulados para demonstração")
        
        np.random.seed(42)
        n_records = 1000
        
        data = {
            'cve_id': [f'CVE-2024-{i:04d}' for i in range(1, n_records+1)],
            'vendor_project': np.random.choice(['Microsoft', 'Adobe', 'Google', 'Apple', 'Linux'], n_records),
            'product': np.random.choice(['Windows', 'Acrobat', 'Chrome', 'iOS', 'Kernel'], n_records),
            'vulnerability_name': np.random.choice(['RCE', 'XSS', 'SQLi', 'PrivEsc', 'DoS'], n_records),
            'date_added': pd.date_range(start='2024-01-01', periods=n_records, freq='D'),
            'due_date': pd.date_range(start='2024-02-01', periods=n_records, freq='D'),
            'required_action': np.random.choice(['Patch', 'Mitigate', 'Monitor'], n_records),
            'known_ransomware_campaign_use': np.random.choice(['Known', 'Unknown'], n_records, p=[0.3, 0.7]),
            'score_cvss': np.random.uniform(4.0, 10.0, n_records).round(1),
            'attack_vector': np.random.choice(['Network', 'Adjacent', 'Local', 'Physical'], n_records),
            'privileges_required': np.random.choice(['None', 'Low', 'High'], n_records),
            'user_interaction': np.random.choice(['None', 'Required'], n_records)
        }
        
        df = pd.DataFrame(data)
        df['data_extracao'] = datetime.now()
        df['fonte'] = 'SIMULADO_CISA'
        
        bronze_path = self.raw_path / f"sample_simulado.parquet"
        df.to_parquet(bronze_path, index=False)
        
        self.bronze_df = df
        return df
    
    def transform_to_silver(self):
        """
        Camada SILVER: Limpeza, padronização e enriquecimento
        """
        print("\n🔨 Transformando para camada SILVER...")
        
        if self.bronze_df is None:
            raise ValueError("Execute extract primeiro!")
        
        df = self.bronze_df.copy()
        
        # === TÉCNICAS AVANÇADAS DE PANDAS ===
        
        # 1. Padronizar nomes de colunas
        df.columns = (df.columns
                      .str.lower()
                      .str.replace(' ', '_')
                      .str.replace('-', '_'))
        
        # 2. Tratar datas
        if 'date_added' in df.columns:
            df['date_added'] = pd.to_datetime(df['date_added'])
            df['year_added'] = df['date_added'].dt.year
            df['month_added'] = df['date_added'].dt.month
            df['quarter_added'] = df['date_added'].dt.quarter
            df['days_since_added'] = (datetime.now() - df['date_added']).dt.days
        
        # 3. TRANSFORM: criar coluna com média do grupo (sem reduzir dados)
        df['avg_score_by_vendor'] = df.groupby('vendor_project')['score_cvss'].transform('mean')
        
        # 4. TRANSFORM: rank dentro de cada grupo (window function)
        df['rank_by_vendor'] = df.groupby('vendor_project')['score_cvss'].rank(
            method='dense', 
            ascending=False
        )
        
        # 5. Classificação customizada com APPLY
        def classify_risk(row):
            if row['score_cvss'] >= 9.0 and row['known_ransomware_campaign_use'] == 'Known':
                return 'CRITICAL'
            elif row['score_cvss'] >= 7.0:
                return 'HIGH'
            elif row['score_cvss'] >= 4.0:
                return 'MEDIUM'
            else:
                return 'LOW'
        
        df['risk_level'] = df.apply(classify_risk, axis=1)
        
        # 6. One-hot encoding para variáveis categóricas
        attack_dummies = pd.get_dummies(df['attack_vector'], prefix='vector')
        df = pd.concat([df, attack_dummies], axis=1)
        
        # 7. Feature engineering avançado
        df['is_critical_vendor'] = df['vendor_project'].isin(['Microsoft', 'Adobe']).astype(int)
        df['score_binned'] = pd.cut(df['score_cvss'], 
                                     bins=[0, 4, 7, 9, 10],
                                     labels=['Baixo', 'Médio', 'Alto', 'Crítico'])
        
        # 8. Rolling window (média móvel por severidade)
        if len(df) > 30:
            df_sorted = df.sort_values('date_added')
            df['rolling_avg_score_30d'] = (
                df_sorted['score_cvss']
                .rolling(window=30, min_periods=1)
                .mean()
                .values
            )
        
        # Salvar camada SILVER
        silver_path = self.processed_path / f"silver_vulnerabilities.parquet"
        df.to_parquet(silver_path, index=False)
        
        self.silver_df = df
        print(f"   ✅ Silver gerada: {len(df)} registros, {len(df.columns)} colunas")
        print(f"   💾 Salvos em: {silver_path}")
        
        return df
    
    def build_gold_layer(self):
        """
        Camada GOLD: Agregações de negócio para relatórios
        """
        print("\n📊 Construindo camada GOLD...")
        
        if self.silver_df is None:
            raise ValueError("Execute transform primeiro!")
        
        df = self.silver_df
        
        # === GOLD 1: Resumo por vendor ===
        gold_vendor = (df.groupby('vendor_project')
                       .agg({
                           'cve_id': 'count',
                           'score_cvss': ['mean', 'max', 'std'],
                           'risk_level': lambda x: (x == 'CRITICAL').sum(),
                           'known_ransomware_campaign_use': lambda x: (x == 'Known').sum()
                       })
                       .round(2))
        
        # Achatar colunas multinível
        gold_vendor.columns = ['_'.join(col).strip() for col in gold_vendor.columns.values]
        gold_vendor = gold_vendor.reset_index()
        gold_vendor['pct_critical'] = (gold_vendor['risk_level_<lambda_0>'] / 
                                        gold_vendor['cve_id_count'] * 100).round(1)
        
        self.gold_dfs['vendor_summary'] = gold_vendor
        
        # === GOLD 2: Análise temporal ===
        gold_temporal = pd.pivot_table(
            df,
            values='cve_id',
            index='year_added',
            columns='risk_level',
            aggfunc='count',
            fill_value=0,
            margins=True,
            margins_name='Total'
        )
        self.gold_dfs['temporal_analysis'] = gold_temporal
        
        # === GOLD 3: Top vulnerabilidades críticas ===
        gold_top_critical = (df[df['risk_level'] == 'CRITICAL']
                             .nlargest(10, 'score_cvss')[['cve_id', 'vendor_project', 
                                                           'product', 'score_cvss', 
                                                           'attack_vector']])
        self.gold_dfs['top_critical'] = gold_top_critical
        
        # === GOLD 4: Matriz de correlação (técnica avançada) ===
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        if len(numeric_cols) > 1:
            corr_matrix = df[numeric_cols].corr()
            self.gold_dfs['correlation_matrix'] = corr_matrix
        
        # Salvar todas as camadas Gold
        for name, gold_df in self.gold_dfs.items():
            gold_path = self.gold_path / f"gold_{name}.csv"
            if isinstance(gold_df, pd.DataFrame):
                gold_df.to_csv(gold_path)
                print(f"   💾 Gold '{name}' salva: {gold_path}")
        
        return self.gold_dfs
    
    def run_pipeline(self):
        """
        Executa pipeline completo
        """
        print("="*60)
        print("🚀 INICIANDO PIPELINE DE ANÁLISE DE SEGURANÇA")
        print("="*60)
        
        self.extract_from_cisa()
        self.transform_to_silver()
        self.build_gold_layer()
        
        print("\n" + "="*60)
        print("✅ PIPELINE CONCLUÍDO COM SUCESSO!")
        print("="*60)
        
        return self


# Execução standalone
if __name__ == "__main__":
    pipeline = SecurityAnalyticsETL()
    pipeline.run_pipeline()