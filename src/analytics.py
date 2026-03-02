"""
Módulo de análises avançadas para o projeto de cibersegurança
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path

class SecurityAnalytics:
    """
    Gera relatórios e visualizações para a camada Gold
    """
    
    def __init__(self, gold_path="data/gold"):
        self.gold_path = Path(gold_path)
        self.gold_path.mkdir(exist_ok=True)
    
    def generate_executive_report(self, df_silver):
        """
        Gera relatório executivo com principais métricas
        """
        print("\n📋 GERANDO RELATÓRIO EXECUTIVO")
        
        report = {
            'data_analise': pd.Timestamp.now(),
            'total_vulnerabilidades': len(df_silver),
            'total_vendors_afetados': df_silver['vendor_project'].nunique(),
            'media_score_cvss': df_silver['score_cvss'].mean().round(2),
            'max_score_cvss': df_silver['score_cvss'].max(),
            'percentual_critico': (df_silver['risk_level'] == 'CRITICAL').mean() * 100,
            'vulnerabilidades_ransomware': df_silver[df_silver['known_ransomware_campaign_use'] == 'Known'].shape[0],
            'top_3_vendors': df_silver['vendor_project'].value_counts().head(3).to_dict(),
            'attack_vector_mais_comum': df_silver['attack_vector'].mode()[0] if not df_silver.empty else 'N/A'
        }
        
        # Salvar relatório
        report_df = pd.DataFrame([report])
        report_path = self.gold_path / "executive_report.csv"
        report_df.to_csv(report_path, index=False)
        
        print("   ✅ Relatório executivo gerado")
        for k, v in report.items():
            if not isinstance(v, dict):
                print(f"      {k}: {v}")
        
        return report
    
    def create_visualizations(self, df_silver):
        """
        Cria visualizações para apresentação
        """
        print("\n📊 GERANDO VISUALIZAÇÕES")
        
        # Configurar estilo
        plt.style.use('seaborn-v0_8-darkgrid')
        
        # 1. Top 10 vendors por vulnerabilidades
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        
        # Gráfico 1: Top vendors
        top_vendors = df_silver['vendor_project'].value_counts().head(10)
        top_vendors.plot(kind='barh', ax=axes[0,0], color='coral')
        axes[0,0].set_title('Top 10 Vendors com Mais Vulnerabilidades')
        axes[0,0].set_xlabel('Número de Vulnerabilidades')
        
        # Gráfico 2: Distribuição de scores CVSS
        axes[0,1].hist(df_silver['score_cvss'], bins=20, color='skyblue', edgecolor='black')
        axes[0,1].axvline(df_silver['score_cvss'].mean(), color='red', linestyle='--', label='Média')
        axes[0,1].set_title('Distribuição de Scores CVSS')
        axes[0,1].set_xlabel('Score CVSS')
        axes[0,1].set_ylabel('Frequência')
        axes[0,1].legend()
        
        # Gráfico 3: Vulnerabilidades por ano
        if 'year_added' in df_silver.columns:
            df_silver['year_added'].value_counts().sort_index().plot(
                kind='line', marker='o', ax=axes[1,0], color='green')
            axes[1,0].set_title('Vulnerabilidades por Ano')
            axes[1,0].set_xlabel('Ano')
            axes[1,0].set_ylabel('Quantidade')
        
        # Gráfico 4: Matriz de calor de risco
        risk_pivot = pd.crosstab(
            df_silver['vendor_project'].head(20), 
            df_silver['risk_level'],
            normalize='index'
        ) * 100
        sns.heatmap(risk_pivot, annot=True, fmt='.1f', cmap='YlOrRd', ax=axes[1,1])
        axes[1,1].set_title('Distribuição de Risco por Vendor (%)')
        
        plt.tight_layout()
        
        # Salvar figura
        viz_path = self.gold_path / "visualizacoes.png"
        plt.savefig(viz_path, dpi=150, bbox_inches='tight')
        print(f"   ✅ Visualizações salvas em: {viz_path}")
        
        plt.close()
        
        return viz_path
    
    def generate_conformity_report(self, df_silver, framework="NIST"):
        """
        Gera relatório simulado de conformidade com frameworks
        """
        print(f"\n🔒 GERANDO RELATÓRIO DE CONFORMIDADE ({framework})")
        
        # Simular métricas de conformidade
        np.random.seed(42)
        
        compliance_metrics = {
            'framework': framework,
            'data_avaliacao': pd.Timestamp.now(),
            'pontuacao_geral': np.random.uniform(75, 95),
            'controles_implementados': np.random.randint(80, 120),
            'controles_nao_implementados': np.random.randint(5, 20),
            'vulnerabilidades_criticas_abertas': df_silver[df_silver['risk_level'] == 'CRITICAL'].shape[0],
            'tempo_medio_remediacao_dias': np.random.randint(30, 90),
            'status_geral': np.random.choice(['Bom', 'Regular', 'Crítico'], p=[0.6, 0.3, 0.1])
        }
        
        # Mapear para NIST CSF
        nist_functions = ['Identify', 'Protect', 'Detect', 'Respond', 'Recover']
        for func in nist_functions:
            compliance_metrics[f'nist_{func.lower()}'] = np.random.uniform(70, 95)
        
        # Salvar relatório
        compliance_df = pd.DataFrame([compliance_metrics])
        comp_path = self.gold_path / f"compliance_{framework.lower()}.csv"
        compliance_df.to_csv(comp_path, index=False)
        
        print(f"   ✅ Relatório de conformidade gerado")
        print(f"   📊 Pontuação {framework}: {compliance_metrics['pontuacao_geral']:.1f}")
        print(f"   🏷️  Status: {compliance_metrics['status_geral']}")
        
        return compliance_metrics


# Exemplo de uso
if __name__ == "__main__":
    # Carregar dados
    try:
        df = pd.read_parquet("data/processed/silver_vulnerabilities.parquet")
        
        analytics = SecurityAnalytics()
        analytics.generate_executive_report(df)
        analytics.create_visualizations(df)
        analytics.generate_conformity_report(df, "NIST")
        analytics.generate_conformity_report(df, "LGPD")
        
    except FileNotFoundError:
        print("Execute primeiro o pipeline ETL!")