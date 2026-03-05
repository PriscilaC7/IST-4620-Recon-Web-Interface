import gradio as gr
import networkx as nx
import matplotlib.pyplot as plt
import json
import os

from recon_engine import perform_recon
from crawler import passive_crawl
from ai_summary import generate_summary
from report_generator import export_json, export_markdown, export_pdf

def build_graph(domain, assets):
    G = nx.Graph()
    G.add_node(domain, color='red', size=800)
    
    for page in assets.get("pages", []):
        G.add_node(page, color='blue', size=300)
        G.add_edge(domain, page)
        
    for script in assets.get("scripts", []):
        G.add_node(script, color='green', size=200)
        # Connect scripts to the first page (simplified for visualization)
        if assets.get("pages"):
            G.add_edge(assets["pages"][0], script)
            
    fig = plt.figure(figsize=(10, 6))
    colors = [node[1]['color'] for node in G.nodes(data=True)]
    sizes = [node[1]['size'] for node in G.nodes(data=True)]
    
    pos = nx.spring_layout(G)
    nx.draw(G, pos, with_labels=False, node_color=colors, node_size=sizes, edge_color="gray", alpha=0.7)
    plt.title("Asset Relationship Visualization (Red=Domain, Blue=Pages, Green=Scripts)")
    return fig

def run_dashboard(url, scope, auth):
    if not auth:
        raise gr.Error("You must confirm authorization to test this target.")
    if not url:
        raise gr.Error("Target URL is required.")
        
    # 1. Run Recon
    recon_results = perform_recon(url)
    domain = recon_results["domain"]
    
    # 2. Run Passive Crawl
    assets = passive_crawl(url, max_pages=5)
    recon_results["discovered_assets"] = assets
    
    # 3. AI Analysis
    ai_report = generate_summary(recon_results)
    
    # 4. Generate Graph
    fig = build_graph(domain, assets)
    
    # 5. Generate Reports
    json_path = export_json(recon_results, scope, auth)
    md_path = export_markdown(recon_results, ai_report, scope)
    pdf_path = export_pdf(ai_report, scope)
    
    # Format outputs for UI
    dns_out = json.dumps(recon_results["dns"], indent=2)
    ssl_out = json.dumps(recon_results["ssl"], indent=2)
    web_out = json.dumps(recon_results["web_analysis"], indent=2)
    files_out = json.dumps(recon_results["public_files"], indent=2)
    assets_out = json.dumps(assets, indent=2)
    
    return dns_out, ssl_out, web_out, files_out, assets_out, ai_report, fig, [json_path, md_path, pdf_path]

# Gradio Interface
with gr.Blocks(theme=gr.themes.Soft()) as demo:
    gr.Markdown("# 🛡️ Ethical Reconnaissance Dashboard")
    gr.Markdown("### Disclaimer: This tool is strictly for learning, blue-team awareness, and authorized testing. It only performs passive, publicly available data collection. No active exploitation or brute-forcing is performed.")
    
    with gr.Row():
        with gr.Column():
            url_input = gr.Textbox(label="Target URL or Domain", placeholder="https://example.com")
            scope_input = gr.Textbox(label="Scope Description", lines=2, placeholder="Briefly describe the authorized scope...")
            auth_check = gr.Checkbox(label="I confirm I have authorization to perform passive reconnaissance on this target.", value=False)
            run_btn = gr.Button("Run Passive Recon", variant="primary")
            
    with gr.Tabs():
        with gr.TabItem("DNS & WHOIS"):
            dns_output = gr.Code(label="DNS & WHOIS Records", language="json")
        with gr.TabItem("SSL Certificate"):
            ssl_output = gr.Code(label="SSL Analysis", language="json")
        with gr.TabItem("Web & Headers"):
            web_output = gr.Code(label="HTTP Security Headers & Tech Stack", language="json")
        with gr.TabItem("Discovered Assets & Files"):
            files_output = gr.Code(label="Robots.txt & Sitemap", language="json")
            assets_output = gr.Code(label="Crawled Pages & Scripts", language="json")
        with gr.TabItem("Asset Graph"):
            graph_output = gr.Plot(label="Infrastructure Visualization")
        with gr.TabItem("AI Recon Summary"):
            ai_output = gr.Markdown(label="Security Insights & Classification")
            
    with gr.Row():
        export_files = gr.File(label="Download Reconnaissance Reports")

    run_btn.click(
        fn=run_dashboard,
        inputs=[url_input, scope_input, auth_check],
        outputs=[dns_output, ssl_output, web_output, files_output, assets_output, ai_output, graph_output, export_files]
    )

if __name__ == "__main__":
    demo.launch(server_name="0.0.0.0", server_port=7860)
