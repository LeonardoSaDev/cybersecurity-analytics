"""
Pipeline ETL para análise de vulnerabilidades CISA KEV
Arquitetura Medalhão: Bronze → Silver → Gold
Dados reais do catálogo de vulnerabilidades exploradas
"""

import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

class CisaKEVAnalyzer:
    """
    Pipeline completo de análise de vulnerabilidades CISA KEV
    Demonstra técnicas avançadas de Pandas + conceitos Snowflake
    """
    
    def __init__(self, data_path="data/raw/known_exploited_vulnerabilities.csv"):
        self.data_path = Path(data_path)
        self.base_dir = Path(__file__).parent.parent
        
        # Criar diretórios
        for dir_name in ['data/raw', 'data/processed', 'data/gold', 'outputs']:
            (self.base_dir / dir_name).mkdir(parents=True, exist_ok=True)
        
        self.bronze_df = None
        self.silver_df = None
        self.gold_dfs = {}
    
    def extract_bronze(self):
        """
        Camada BRONZE: dados brutos como estão
        """
        print("\n" + "="*60)
        print("📥 CAMADA BRONZE: Extraindo dados brutos")
        print("="*60)
        
        # Carregar CSV
        df = pd.read_csv(self.data_path)
        
        # Salvar cópia dos dados brutos
        bronze_path = self.base_dir / 'data/raw' / 'bronze_cisa_kev.parquet'
        df.to_parquet(bronze_path, index=False)
        
        self.bronze_df = df
        
        print(f"   ✅ Registros carregados: {len(df):,}")
        print(f"   ✅ Colunas: {list(df.columns)}")
        print(f"   ✅ Período: {df['dateAdded'].min()} até {df['dateAdded'].max()}")
        print(f"   💾 Salvos em: {bronze_path}")
        
        return self
    
    def transform_to_silver(self):
        """
        Camada SILVER: limpeza, padronização e enriquecimento
        Técnicas AVANÇADAS de Pandas demonstradas
        """
        print("\n" + "="*60)
        print("🔨 CAMADA SILVER: Transformando dados")
        print("="*60)
        
        if self.bronze_df is None:
            raise ValueError("Execute extract_bronze() primeiro!")
        
        df = self.bronze_df.copy()
        
        # === 1. PADRONIZAÇÃO DE COLUNAS ===
        print("\n   📋 Padronizando colunas...")
        df.columns = [col.lower() for col in df.columns]
        
        # Mapeamento para nomes mais legíveis
        column_map = {
            'cveid': 'cve_id',
            'vendorproject': 'vendor',
            'product': 'product',
            'vulnerabilityname': 'vuln_name',
            'dateadded': 'date_added',
            'shortdescription': 'description',
            'requiredaction': 'required_action',
            'duedate': 'due_date',
            'knownransomwarecampaignuse': 'ransomware_known',
            'notes': 'notes',
            'cwes': 'cwe_list'
        }
        df = df.rename(columns=column_map)
        
        # === 2. TRATAMENTO DE DATAS (TÉCNICA AVANÇADA) ===
        print("   📅 Processando datas...")
        df['date_added'] = pd.to_datetime(df['date_added'])
        df['due_date'] = pd.to_datetime(df['due_date'], errors='coerce')
        
        # Feature engineering temporal
        df['year_added'] = df['date_added'].dt.year
        df['month_added'] = df['date_added'].dt.month
        df['quarter_added'] = df['date_added'].dt.quarter
        df['week_added'] = df['date_added'].dt.isocalendar().week
        df['day_of_week'] = df['date_added'].dt.day_name()
        df['days_to_due'] = (df['due_date'] - df['date_added']).dt.days
        df['days_since_added'] = (pd.Timestamp.now() - df['date_added']).dt.days
        
        # === 3. PROCESSAMENTO DE CWE (TÉCNICA AVANÇADA) ===
        print("   🔧 Processando classificações CWE...")
        
        # Extrair CWE principal (primeiro código)
        df['primary_cwe'] = df['cwe_list'].str.split(',').str[0].str.strip()
        
        # Contar número de CWEs por vulnerabilidade
        df['cwe_count'] = df['cwe_list'].str.count(',') + 1
        df['cwe_count'] = df['cwe_count'].fillna(0).astype(int)
        
        # === 4. CLASSIFICAÇÃO DE RISCO (TRANSFORM COM GROUPBY) ===
        print("   ⚠️ Classificando níveis de risco...")
        
        # TÉCNICA 1: transform com groupby (adiciona média sem reduzir linhas)
        df['avg_days_to_due_by_vendor'] = df.groupby('vendor')['days_to_due'].transform('mean').round(0)
        
        # TÉCNICA 2: rank por vendor (window function)
        df['rank_by_vendor'] = df.groupby('vendor')['days_since_added'].rank(
            method='dense', ascending=False
        ).astype(int)
        
        # TÉCNICA 3: classificação customizada com apply
        def classify_risk(row):
            """Classifica risco baseado em ransomware e tempo"""
            if row['ransomware_known'] == 'Known':
                return 'CRITICAL'
            elif row['days_since_added'] < 30:
                return 'HIGH'
            elif row['days_since_added'] < 90:
                return 'MEDIUM'
            else:
                return 'LOW'
        
        df['risk_level'] = df.apply(classify_risk, axis=1)
        
        # === 5. FEATURE ENGINEERING AVANÇADO ===
        print("   🎯 Criando features adicionais...")
        
        # TÉCNICA 4: categorização de tempo
        df['time_category'] = pd.cut(
            df['days_since_added'],
            bins=[0, 30, 90, 180, 365, float('inf')],
            labels=['< 1 mês', '1-3 meses', '3-6 meses', '6-12 meses', '> 1 ano']
        )
        
        # TÉCNICA 5: flags booleanas
        df['is_critical'] = df['risk_level'] == 'CRITICAL'
        df['is_ransomware'] = df['ransomware_known'] == 'Known'
        df['is_recent'] = df['days_since_added'] < 30
        
        # TÉCNICA 6: extrair palavras-chave da descrição (exemplo)
        keywords = ['remote', 'execute', 'privilege', 'bypass', 'memory']
        for kw in keywords:
            df[f'has_{kw}'] = df['description'].str.lower().str.contains(kw, na=False).astype(int)
        
        # === 6. SIMULAÇÃO DE SCORE CVSS (baseado em características) ===
        print("   📊 Simulando scores CVSS...")
        
        # Base: 5.0
        df['cvss_score'] = 5.0
        
        # Ajustes baseados em características
        df.loc[df['ransomware_known'] == 'Known', 'cvss_score'] += 3.0
        df.loc[df['description'].str.contains('remote code|execute', case=False, na=False), 'cvss_score'] += 1.5
        df.loc[df['description'].str.contains('privilege|escalation', case=False, na=False), 'cvss_score'] += 1.0
        df.loc[df['description'].str.contains('bypass', case=False, na=False), 'cvss_score'] += 0.5
        
        # Limitar entre 0 e 10
        df['cvss_score'] = df['cvss_score'].clip(0, 10).round(1)
        
        # Categorizar CVSS
        df['cvss_severity'] = pd.cut(
            df['cvss_score'],
            bins=[0, 4, 7, 9, 10],
            labels=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        )
        
        # Salvar camada SILVER
        silver_path = self.base_dir / 'data/processed' / 'silver_vulnerabilities.parquet'
        df.to_parquet(silver_path, index=False)
        
        self.silver_df = df
        
        print(f"\n   ✅ Silver gerada: {len(df):,} registros, {len(df.columns)} colunas")
        print(f"   💾 Salvos em: {silver_path}")
        
        return self
    
    def build_gold_layer(self):
        """
        Camada GOLD: agregações estratégicas para negócio
        Múltiplas visões dos dados
        """
        print("\n" + "="*60)
        print("📊 CAMADA GOLD: Construindo visões de negócio")
        print("="*60)
        
        if self.silver_df is None:
            raise ValueError("Execute transform_to_silver() primeiro!")
        
        df = self.silver_df
        
        # === GOLD 1: Resumo por Vendor ===
        print("\n   🏢 Gold 1: Análise por fabricante...")
        gold_vendor = (df.groupby('vendor')
                       .agg({
                           'cve_id': 'count',
                           'cvss_score': ['mean', 'max', 'std'],
                           'is_critical': 'sum',
                           'is_ransomware': 'sum',
                           'days_to_due': 'mean',
                           'vendor': 'first'  # dummy para contar
                       })
                       .round(2))
        
        # Achatar colunas multinível
        gold_vendor.columns = ['_'.join(col).strip() for col in gold_vendor.columns.values]
        gold_vendor = gold_vendor.reset_index()
        gold_vendor['critical_percent'] = (gold_vendor['is_critical_sum'] / 
                                            gold_vendor['cve_id_count'] * 100).round(1)
        gold_vendor = gold_vendor.sort_values('cve_id_count', ascending=False)
        
        self.gold_dfs['vendor_summary'] = gold_vendor
        
        # === GOLD 2: Análise Temporal ===
        print("   📅 Gold 2: Tendências temporais...")
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
        
        # === GOLD 3: Top Vulnerabilidades Críticas ===
        print("   🔥 Gold 3: Top vulnerabilidades críticas...")
        gold_top_critical = (df[df['is_critical']]
                             .nlargest(15, 'cvss_score')[['cve_id', 'vendor', 'product', 
                                                           'vuln_name', 'cvss_score', 
                                                           'days_since_added']])
        self.gold_dfs['top_critical'] = gold_top_critical
        
        # === GOLD 4: Análise de Ransomware ===
        print("   💀 Gold 4: Vulnerabilidades usadas em ransomware...")
        gold_ransomware = (df[df['is_ransomware']]
                           .groupby('vendor')
                           .agg({
                               'cve_id': 'count',
                               'cvss_score': 'mean',
                               'product': lambda x: ', '.join(x.head(3))
                           })
                           .round(1)
                           .sort_values('cve_id', ascending=False))
        self.gold_dfs['ransomware_analysis'] = gold_ransomware
        
        # === GOLD 5: Matriz de Correlação ===
        print("   🔗 Gold 5: Correlações entre métricas...")
        numeric_cols = ['cvss_score', 'days_to_due', 'days_since_added', 
                        'cwe_count', 'is_critical', 'is_ransomware']
        corr_matrix = df[numeric_cols].corr()
        self.gold_dfs['correlation_matrix'] = corr_matrix
        
        # === GOLD 6: Análise de CWEs mais comuns ===
        print("   📋 Gold 6: Top CWEs...")
        # Explodir lista de CWEs
        cwes_exploded = df.assign(cwe=df['cwe_list'].str.split(',')).explode('cwe')
        cwes_exploded['cwe'] = cwes_exploded['cwe'].str.strip()
        
        gold_cwes = (cwes_exploded['cwe']
                     .value_counts()
                     .head(20)
                     .reset_index())
        gold_cwes.columns = ['cwe', 'count']
        self.gold_dfs['cwe_ranking'] = gold_cwes
        
        # Salvar todas as camadas Gold
        gold_dir = self.base_dir / 'data/gold'
        for name, gold_df in self.gold_dfs.items():
            # Tratar MultiIndex se necessário
            if isinstance(gold_df, pd.DataFrame):
                if isinstance(gold_df.columns, pd.MultiIndex):
                    gold_df.columns = ['_'.join(col).strip() for col in gold_df.columns.values]
                
                gold_path = gold_dir / f'gold_{name}.csv'
                gold_df.to_csv(gold_path)
                print(f"   💾 Gold '{name}' salva: {gold_path}")
        
        return self
    
    def run_pipeline(self):
        """
        Executa pipeline completo
        """
        print("\n" + "="*60)
        print("🚀 INICIANDO PIPELINE DE ANÁLISE CISA KEV")
        print("="*60)
        
        self.extract_bronze()
        self.transform_to_silver()
        self.build_gold_layer()
        
        print("\n" + "="*60)
        print("✅ PIPELINE CONCLUÍDO COM SUCESSO!")
        print("="*60)
        
        return self


# Execução
if __name__ == "__main__":
    analyzer = CisaKEVAnalyzer()
    analyzer.run_pipeline()