"""
Módulo de análises estratégicas para dados CISA KEV
Gera relatórios executivos e visualizações
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
from datetime import datetime

class CisaAnalytics:
    """
    Gera insights estratégicos a partir dos dados CISA KEV
    """
    
    def __init__(self, silver_path="data/processed/silver_vulnerabilities.parquet"):
        self.base_dir = Path(__file__).parent.parent
        self.silver_df = pd.read_parquet(self.base_dir / silver_path)
        self.outputs_dir = self.base_dir / 'outputs'
        self.outputs_dir.mkdir(exist_ok=True)
        
        # Configurar estilo
        plt.style.use('seaborn-v0_8-darkgrid')
        sns.set_palette("husl")
    
    def generate_executive_report(self):
        """
        Relatório executivo com principais métricas
        """
        print("\n" + "="*60)
        print("📋 GERANDO RELATÓRIO EXECUTIVO")
        print("="*60)
        
        df = self.silver_df
        
        report = {
            'data_analise': datetime.now().strftime('%Y-%m-%d'),
            'total_vulnerabilidades': len(df),
            'total_fabricantes_afetados': df['vendor'].nunique(),
            'total_produtos_afetados': df['product'].nunique(),
            'vulnerabilidades_criticas': df['is_critical'].sum(),
            'percentual_critico': (df['is_critical'].mean() * 100).round(1),
            'vulnerabilidades_ransomware': df['is_ransomware'].sum(),
            'percentual_ransomware': (df['is_ransomware'].mean() * 100).round(1),
            'media_cvss': df['cvss_score'].mean().round(1),
            'mediana_cvss': df['cvss_score'].median().round(1),
            'maior_cvss': df['cvss_score'].max(),
            'media_dias_para_correcao': df['days_to_due'].mean().round(0),
            'vulnerabilidade_mais_antiga_dias': df['days_since_added'].max(),
            'top_3_fabricantes': df['vendor'].value_counts().head(3).to_dict(),
            'cwe_mais_comum': df['cwe_list'].str.split(',').explode().str.strip().mode()[0]
        }
        
        # Adicionar análise por ano
        ano_atual = datetime.now().year
        report['vulnerabilidades_ano_atual'] = df[df['year_added'] == ano_atual].shape[0]
        
        # Salvar relatório
        report_df = pd.DataFrame([report])
        report_path = self.outputs_dir / 'executive_report.csv'
        report_df.to_csv(report_path, index=False)
        
        print("\n📊 PRINCIPAIS MÉTRICAS:")
        for k, v in report.items():
            if not isinstance(v, dict):
                print(f"   {k}: {v}")
        
        return report
    
    def create_strategic_visualizations(self):
        """
        Cria visualizações estratégicas para apresentação
        """
        print("\n" + "="*60)
        print("📊 GERANDO VISUALIZAÇÕES ESTRATÉGICAS")
        print("="*60)
        
        df = self.silver_df
        
        # Figura com múltiplos gráficos
        fig = plt.figure(figsize=(20, 16))
        
        # 1. Top 15 fabricantes mais afetados
        ax1 = plt.subplot(3, 3, 1)
        top_vendors = df['vendor'].value_counts().head(15)
        top_vendors.plot(kind='barh', ax=ax1, color='coral')
        ax1.set_title('Top 15 Fabricantes com Mais Vulnerabilidades', fontsize=12, fontweight='bold')
        ax1.set_xlabel('Número de Vulnerabilidades')
        ax1.invert_yaxis()
        
        # 2. Distribuição de CVSS scores
        ax2 = plt.subplot(3, 3, 2)
        ax2.hist(df['cvss_score'], bins=20, color='skyblue', edgecolor='black', alpha=0.7)
        ax2.axvline(df['cvss_score'].mean(), color='red', linestyle='--', label=f'Média: {df["cvss_score"].mean():.1f}')
        ax2.axvline(df['cvss_score'].median(), color='green', linestyle='--', label=f'Mediana: {df["cvss_score"].median():.1f}')
        ax2.set_title('Distribuição de Scores CVSS', fontsize=12, fontweight='bold')
        ax2.set_xlabel('Score CVSS')
        ax2.set_ylabel('Frequência')
        ax2.legend()
        
        # 3. Evolução temporal
        ax3 = plt.subplot(3, 3, 3)
        temporal = df['year_added'].value_counts().sort_index()
        ax3.plot(temporal.index, temporal.values, marker='o', linewidth=2, markersize=8)
        ax3.fill_between(temporal.index, temporal.values, alpha=0.3)
        ax3.set_title('Vulnerabilidades por Ano', fontsize=12, fontweight='bold')
        ax3.set_xlabel('Ano')
        ax3.set_ylabel('Quantidade')
        ax3.grid(True, alpha=0.3)
        
        # 4. Vulnerabilidades por nível de risco
        ax4 = plt.subplot(3, 3, 4)
        risk_counts = df['risk_level'].value_counts()
        colors = {'CRITICAL': 'red', 'HIGH': 'orange', 'MEDIUM': 'yellow', 'LOW': 'green'}
        risk_counts.plot(kind='pie', ax=ax4, autopct='%1.1f%%', 
                        colors=[colors.get(x, 'gray') for x in risk_counts.index],
                        explode=[0.05 if x == 'CRITICAL' else 0 for x in risk_counts.index])
        ax4.set_title('Distribuição por Nível de Risco', fontsize=12, fontweight='bold')
        ax4.set_ylabel('')
        
        # 5. Ransomware vs Não Ransomware
        ax5 = plt.subplot(3, 3, 5)
        ransomware_counts = df['ransomware_known'].value_counts()
        ax5.bar(ransomware_counts.index, ransomware_counts.values, 
                color=['red' if x == 'Known' else 'green' for x in ransomware_counts.index])
        ax5.set_title('Vulnerabilidades Usadas em Ransomware', fontsize=12, fontweight='bold')
        ax5.set_ylabel('Quantidade')
        ax5.set_xlabel('Uso em Ransomware')
        
        # 6. Top 10 produtos mais vulneráveis
        ax6 = plt.subplot(3, 3, 6)
        top_products = df['product'].value_counts().head(10)
        top_products.plot(kind='bar', ax=ax6, color='purple', alpha=0.7)
        ax6.set_title('Top 10 Produtos Mais Vulneráveis', fontsize=12, fontweight='bold')
        ax6.set_xlabel('Produto')
        ax6.set_ylabel('Quantidade')
        ax6.tick_params(axis='x', rotation=45)
        
        # 7. Tempo para correção por fabricante
        ax7 = plt.subplot(3, 3, 7)
        vendor_time = df.groupby('vendor')['days_to_due'].mean().sort_values(ascending=False).head(10)
        vendor_time.plot(kind='bar', ax=ax7, color='teal', alpha=0.7)
        ax7.set_title('Média de Dias para Correção por Fabricante (Top 10)', fontsize=12, fontweight='bold')
        ax7.set_xlabel('Fabricante')
        ax7.set_ylabel('Dias Médios')
        ax7.tick_params(axis='x', rotation=45)
        
        # 8. Top 10 CWEs mais comuns
        ax8 = plt.subplot(3, 3, 8)
        cwes = df['cwe_list'].str.split(',').explode().str.strip().value_counts().head(10)
        cwes.plot(kind='barh', ax=ax8, color='brown', alpha=0.7)
        ax8.set_title('Top 10 CWEs Mais Comuns', fontsize=12, fontweight='bold')
        ax8.set_xlabel('Frequência')
        ax8.invert_yaxis()
        
        # 9. Correlação entre métricas
        ax9 = plt.subplot(3, 3, 9)
        numeric_cols = ['cvss_score', 'days_to_due', 'days_since_added', 'cwe_count']
        corr = df[numeric_cols].corr()
        sns.heatmap(corr, annot=True, fmt='.2f', cmap='coolwarm', center=0,
                   square=True, ax=ax9, cbar_kws={'shrink': 0.8})
        ax9.set_title('Matriz de Correlação', fontsize=12, fontweight='bold')
        
        plt.tight_layout()
        
        # Salvar figura
        viz_path = self.outputs_dir / 'strategic_visualizations.png'
        plt.savefig(viz_path, dpi=150, bbox_inches='tight')
        plt.close()
        
        print(f"   ✅ Visualizações salvas em: {viz_path}")
        
        return viz_path
    
    def generate_ransomware_report(self):
        """
        Relatório específico sobre vulnerabilidades usadas em ransomware
        """
        print("\n" + "="*60)
        print("💀 GERANDO RELATÓRIO DE RANSOMWARE")
        print("="*60)
        
        df = self.silver_df
        df_ransom = df[df['is_ransomware']].copy()
        
        if len(df_ransom) == 0:
            print("   ⚠️ Nenhuma vulnerabilidade de ransomware encontrada")
            return None
        
        report = {
            'total_ransomware': len(df_ransom),
            'percentual_do_total': (len(df_ransom) / len(df) * 100).round(1),
            'fabricantes_afetados': df_ransom['vendor'].nunique(),
            'media_cvss_ransomware': df_ransom['cvss_score'].mean().round(1),
            'maior_cvss_ransomware': df_ransom['cvss_score'].max(),
            'vulnerabilidades_criticas': (df_ransom['is_critical'].sum()),
            'tempo_medio_correcao_dias': df_ransom['days_to_due'].mean().round(0)
        }
        
        # Top fabricantes em ransomware
        top_vendors_ransom = df_ransom['vendor'].value_counts().head(10)
        
        # Salvar relatório
        report_df = pd.DataFrame([report])
        report_path = self.outputs_dir / 'ransomware_report.csv'
        report_df.to_csv(report_path, index=False)
        
        top_vendors_path = self.outputs_dir / 'top_vendors_ransomware.csv'
        top_vendors_ransom.to_csv(top_vendors_path)
        
        print("\n📊 MÉTRICAS DE RANSOMWARE:")
        for k, v in report.items():
            print(f"   {k}: {v}")
        
        print(f"\n   💾 Relatórios salvos em: {self.outputs_dir}")
        
        return report
    
    def generate_compliance_report(self):
        """
        Relatório simulando conformidade com frameworks (NIST/LGPD)
        """
        print("\n" + "="*60)
        print("🔒 GERANDO RELATÓRIO DE CONFORMIDADE")
        print("="*60)
        
        df = self.silver_df
        
        # Simular métricas de conformidade
        compliance_metrics = {
            'framework': 'NIST CSF',
            'data_avaliacao': datetime.now().strftime('%Y-%m-%d'),
            'pontuacao_geral': np.random.uniform(75, 92),
            'controles_implementados': np.random.randint(85, 110),
            'controles_nao_implementados': np.random.randint(10, 25),
            'vulnerabilidades_criticas_abertas': df[df['risk_level'] == 'CRITICAL'].shape[0],
            'vulnerabilidades_high_abertas': df[df['risk_level'] == 'HIGH'].shape[0],
            'tempo_medio_remediacao_dias': df['days_to_due'].mean().round(0),
            'percentual_vulnerabilidades_antigas': (df['days_since_added'] > 365).mean() * 100,
            'status_geral': np.random.choice(['Bom', 'Regular', 'Crítico'], p=[0.5, 0.3, 0.2])
        }
        
        # Adicionar funções NIST
        nist_functions = ['Identify', 'Protect', 'Detect', 'Respond', 'Recover']
        for func in nist_functions:
            compliance_metrics[f'nist_{func.lower()}_score'] = np.random.uniform(70, 95).round(1)
        
        # Salvar relatório
        compliance_df = pd.DataFrame([compliance_metrics])
        comp_path = self.outputs_dir / 'compliance_report.csv'
        compliance_df.to_csv(comp_path, index=False)
        
        print("\n📊 MÉTRICAS DE CONFORMIDADE:")
        for k, v in compliance_metrics.items():
            if k not in ['data_avaliacao']:
                print(f"   {k}: {v}")
        
        return compliance_metrics


# Execução
if __name__ == "__main__":
    analytics = CisaAnalytics()
    
    # Gerar todos os relatórios
    analytics.generate_executive_report()
    analytics.create_strategic_visualizations()
    analytics.generate_ransomware_report()
    analytics.generate_compliance_report()