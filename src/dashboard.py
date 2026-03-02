"""
Dashboard interativo para análise de vulnerabilidades CISA KEV
Criado com Streamlit para visualização dos dados e insights
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import matplotlib.pyplot as plt
from pathlib import Path
import sys
from datetime import datetime

# Adicionar src ao path para importar módulos
sys.path.append(str(Path(__file__).parent))
from etl_pipeline import CisaKEVAnalyzer

# ============================================
# CONFIGURAÇÕES DA PÁGINA
# ============================================
st.set_page_config(
    page_title="CISA KEV Analytics Dashboard",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================
# CARREGAMENTO DE DADOS (com cache)
# ============================================
@st.cache_data
def load_data():
    """Carrega os dados processados com cache"""
    base_dir = Path(__file__).parent.parent
    silver_path = base_dir / 'data' / 'processed' / 'silver_vulnerabilities.parquet'
    
    if not silver_path.exists():
        st.warning("⚠️ Dados processados não encontrados. Executando pipeline...")
        analyzer = CisaKEVAnalyzer()
        analyzer.run_pipeline()
    
    df = pd.read_parquet(silver_path)
    return df

@st.cache_data
def load_gold_data():
    """Carrega todas as camadas Gold"""
    base_dir = Path(__file__).parent.parent
    gold_dir = base_dir / 'data' / 'gold'
    
    gold_data = {}
    if gold_dir.exists():
        for file in gold_dir.glob('gold_*.csv'):
            name = file.stem.replace('gold_', '')
            gold_data[name] = pd.read_csv(file)
    
    return gold_data

# ============================================
# SIDEBAR - CONTROLES E FILTROS
# ============================================
st.sidebar.image("https://www.cisa.gov/sites/default/files/images/CISA_Logo_183x133.png", width=200)
st.sidebar.title("🔐 CISA KEV Dashboard")
st.sidebar.markdown("---")

# Carregar dados
with st.spinner("Carregando dados..."):
    df = load_data()
    gold_data = load_gold_data()

# Filtros
st.sidebar.header("🎯 Filtros")

# Filtro por período
years = sorted(df['year_added'].unique(), reverse=True)
selected_years = st.sidebar.multiselect(
    "Anos",
    options=years,
    default=years[:3]  # últimos 3 anos por padrão
)

# Filtro por nível de risco
risk_levels = sorted(df['risk_level'].unique())
selected_risks = st.sidebar.multiselect(
    "Nível de Risco",
    options=risk_levels,
    default=risk_levels
)

# Filtro por ransomware
ransomware_filter = st.sidebar.radio(
    "Uso em Ransomware",
    options=["Todos", "Apenas Known", "Apenas Unknown"],
    index=0
)

# Filtro por fabricante
vendors = sorted(df['vendor'].unique())
selected_vendors = st.sidebar.multiselect(
    "Fabricantes (vazio = todos)",
    options=vendors
)

# Aplicar filtros
filtered_df = df.copy()
if selected_years:
    filtered_df = filtered_df[filtered_df['year_added'].isin(selected_years)]
if selected_risks:
    filtered_df = filtered_df[filtered_df['risk_level'].isin(selected_risks)]
if ransomware_filter == "Apenas Known":
    filtered_df = filtered_df[filtered_df['ransomware_known'] == 'Known']
elif ransomware_filter == "Apenas Unknown":
    filtered_df = filtered_df[filtered_df['ransomware_known'] == 'Unknown']
if selected_vendors:
    filtered_df = filtered_df[filtered_df['vendor'].isin(selected_vendors)]

# Métricas rápidas na sidebar
st.sidebar.markdown("---")
st.sidebar.header("📊 Métricas Rápidas")
st.sidebar.metric("Total Registros", f"{len(filtered_df):,}")
st.sidebar.metric("Fabricantes", filtered_df['vendor'].nunique())
st.sidebar.metric("Vulns Críticas", filtered_df['is_critical'].sum())
st.sidebar.metric("Ransomware", filtered_df['is_ransomware'].sum())

# ============================================
# CABEÇALHO PRINCIPAL
# ============================================
st.title("🔐 CISA Known Exploited Vulnerabilities (KEV)")
st.markdown("""
Este dashboard apresenta análises interativas do catálogo **CISA KEV**, 
que contém vulnerabilidades conhecidas que estão sendo ativamente exploradas.
""")

# ============================================
# LINHA 1: MÉTRICAS PRINCIPAIS
# ============================================
col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    st.metric(
        "Total Vulnerabilidades",
        f"{len(df):,}",
        delta=None
    )

with col2:
    st.metric(
        "Fabricantes Afetados",
        f"{df['vendor'].nunique():,}",
        delta=None
    )

with col3:
    pct_critical = (df['is_critical'].sum() / len(df) * 100)
    st.metric(
        "Vulns Críticas",
        f"{df['is_critical'].sum():,}",
        delta=f"{pct_critical:.1f}% do total"
    )

with col4:
    pct_ransomware = (df['is_ransomware'].sum() / len(df) * 100)
    st.metric(
        "Usadas em Ransomware",
        f"{df['is_ransomware'].sum():,}",
        delta=f"{pct_ransomware:.1f}% do total"
    )

with col5:
    avg_cvss = df['cvss_score'].mean()
    st.metric(
        "Média CVSS",
        f"{avg_cvss:.1f}",
        delta=None
    )

st.markdown("---")

# ============================================
# LINHA 2: GRÁFICOS PRINCIPAIS
# ============================================
col1, col2 = st.columns(2)

with col1:
    st.subheader("📊 Top 15 Fabricantes por Vulnerabilidades")
    
    # Dados para o gráfico
    vendor_counts = filtered_df['vendor'].value_counts().head(15).reset_index()
    vendor_counts.columns = ['vendor', 'count']
    
    fig = px.bar(
        vendor_counts,
        x='count',
        y='vendor',
        orientation='h',
        title="",
        color='count',
        color_continuous_scale='Reds',
        text='count'
    )
    fig.update_layout(
        height=500,
        yaxis={'categoryorder': 'total ascending'},
        xaxis_title="Número de Vulnerabilidades",
        yaxis_title=""
    )
    fig.update_traces(textposition='outside')
    st.plotly_chart(fig, use_container_width=True)

with col2:
    st.subheader("📈 Evolução Temporal")
    
    # Dados temporais
    temporal = filtered_df.groupby(['year_added', 'risk_level']).size().reset_index(name='count')
    
    fig = px.line(
        temporal,
        x='year_added',
        y='count',
        color='risk_level',
        title="",
        markers=True,
        color_discrete_map={
            'CRITICAL': 'red',
            'HIGH': 'orange',
            'MEDIUM': 'yellow',
            'LOW': 'green'
        }
    )
    fig.update_layout(
        height=500,
        xaxis_title="Ano",
        yaxis_title="Número de Vulnerabilidades"
    )
    st.plotly_chart(fig, use_container_width=True)

# ============================================
# LINHA 3: MAIS GRÁFICOS
# ============================================
col1, col2 = st.columns(2)

with col1:
    st.subheader("🥧 Distribuição por Nível de Risco")
    
    risk_dist = filtered_df['risk_level'].value_counts().reset_index()
    risk_dist.columns = ['risk_level', 'count']
    
    colors = {'CRITICAL': 'red', 'HIGH': 'orange', 'MEDIUM': 'yellow', 'LOW': 'green'}
    
    fig = px.pie(
        risk_dist,
        values='count',
        names='risk_level',
        title="",
        color='risk_level',
        color_discrete_map=colors
    )
    fig.update_traces(textposition='inside', textinfo='percent+label')
    fig.update_layout(height=400)
    st.plotly_chart(fig, use_container_width=True)

with col2:
    st.subheader("💀 Ransomware por Fabricante")
    
    # Filtrar apenas ransomware
    ransom_df = filtered_df[filtered_df['is_ransomware']]
    if len(ransom_df) > 0:
        ransom_vendors = ransom_df['vendor'].value_counts().head(10).reset_index()
        ransom_vendors.columns = ['vendor', 'count']
        
        fig = px.bar(
            ransom_vendors,
            x='count',
            y='vendor',
            orientation='h',
            title="Top 10 Fabricantes em Ransomware",
            color='count',
            color_continuous_scale='Reds'
        )
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Nenhuma vulnerabilidade de ransomware com os filtros atuais")

# ============================================
# LINHA 4: ANÁLISE DE CVSS E CORRELAÇÕES
# ============================================
col1, col2 = st.columns(2)

with col1:
    st.subheader("📊 Distribuição de Scores CVSS")
    
    fig = px.histogram(
        filtered_df,
        x='cvss_score',
        nbins=20,
        title="",
        color_discrete_sequence=['skyblue'],
        marginal='box'
    )
    fig.add_vline(
        x=filtered_df['cvss_score'].mean(),
        line_dash="dash",
        line_color="red",
        annotation_text=f"Média: {filtered_df['cvss_score'].mean():.1f}"
    )
    fig.update_layout(height=400)
    st.plotly_chart(fig, use_container_width=True)

with col2:
    st.subheader("⏱️ Dias para Correção por Nível de Risco")
    
    fig = px.box(
        filtered_df,
        x='risk_level',
        y='days_to_due',
        title="",
        color='risk_level',
        color_discrete_map=colors,
        points="outliers"
    )
    fig.update_layout(height=400)
    st.plotly_chart(fig, use_container_width=True)

# ============================================
# LINHA 5: ANÁLISE DE CWE
# ============================================
st.subheader("🔧 Top 20 CWEs Mais Comuns")

# Explodir CWEs
cwes_exploded = filtered_df.assign(
    cwe=filtered_df['cwe_list'].str.split(',')
).explode('cwe')
cwes_exploded['cwe'] = cwes_exploded['cwe'].str.strip()
cwe_counts = cwes_exploded['cwe'].value_counts().head(20).reset_index()
cwe_counts.columns = ['cwe', 'count']

fig = px.bar(
    cwe_counts,
    x='count',
    y='cwe',
    orientation='h',
    title="",
    color='count',
    color_continuous_scale='Viridis',
    text='count'
)
fig.update_layout(
    height=600,
    yaxis={'categoryorder': 'total ascending'},
    xaxis_title="Frequência",
    yaxis_title="CWE"
)
fig.update_traces(textposition='outside')
st.plotly_chart(fig, use_container_width=True)

# ============================================
# LINHA 6: TABELA INTERATIVA
# ============================================
st.markdown("---")
st.subheader("📋 Dados Detalhados")

# Seleção de colunas para exibir
display_cols = ['cve_id', 'vendor', 'product', 'vuln_name', 'risk_level', 
                'cvss_score', 'ransomware_known', 'days_since_added']

# Adicionar busca
search = st.text_input("🔍 Buscar por CVE, fabricante ou produto", "")

if search:
    mask = (
        filtered_df['cve_id'].str.contains(search, case=False, na=False) |
        filtered_df['vendor'].str.contains(search, case=False, na=False) |
        filtered_df['product'].str.contains(search, case=False, na=False) |
        filtered_df['vuln_name'].str.contains(search, case=False, na=False)
    )
    display_df = filtered_df[mask][display_cols]
else:
    display_df = filtered_df[display_cols].head(100)

st.dataframe(
    display_df,
    use_container_width=True,
    height=400,
    column_config={
        'cve_id': 'CVE ID',
        'vendor': 'Fabricante',
        'product': 'Produto',
        'vuln_name': 'Nome',
        'risk_level': 'Risco',
        'cvss_score': 'CVSS',
        'ransomware_known': 'Ransomware',
        'days_since_added': 'Dias desde adição'
    }
)

# Botão para download
csv = display_df.to_csv(index=False)
st.download_button(
    label="📥 Download dos dados filtrados (CSV)",
    data=csv,
    file_name=f"cisa_kev_filtered_{datetime.now().strftime('%Y%m%d')}.csv",
    mime="text/csv"
)

# ============================================
# RODAPÉ
# ============================================
st.markdown("---")
st.markdown(
    """
    <div style='text-align: center'>
        <p>🔐 CISA KEV Analytics Dashboard | Desenvolvido para S4 System</p>
        <p>Fonte: <a href='https://www.cisa.gov/known-exploited-vulnerabilities-catalog'>CISA Known Exploited Vulnerabilities Catalog</a></p>
    </div>
    """,
    unsafe_allow_html=True
)