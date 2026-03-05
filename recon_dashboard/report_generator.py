import json
import os
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

def export_json(data, scope, auth_confirmed, filepath="report.json"):
    export_data = {
        "metadata": {"scope": scope, "authorization_confirmed": auth_confirmed},
        "findings": data
    }
    with open(filepath, 'w') as f:
        json.dump(export_data, f, indent=4, default=str)
    return filepath

def export_markdown(data, ai_summary, scope, filepath="report.md"):
    md_content = f"# Ethical Reconnaissance Report\n\n"
    md_content += f"**Scope:** {scope}\n**Authorized:** Yes\n\n"
    md_content += f"## AI Analysis & Insights\n{ai_summary}\n\n"
    md_content += f"## Raw Findings\n```json\n{json.dumps(data, indent=2, default=str)}\n```"
    
    with open(filepath, 'w') as f:
        f.write(md_content)
    return filepath

def export_pdf(ai_summary, scope, filepath="report.pdf"):
    doc = SimpleDocTemplate(filepath, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    
    story.append(Paragraph("Ethical Reconnaissance Report", styles['Title']))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"<b>Scope:</b> {scope}", styles['Normal']))
    story.append(Paragraph("<b>Authorization Confirmed:</b> Yes", styles['Normal']))
    story.append(Spacer(1, 12))
    
    story.append(Paragraph("AI Analysis & Defensive Insights", styles['Heading2']))
    for line in ai_summary.split('\n'):
        if line.strip():
            story.append(Paragraph(line, styles['Normal']))
            story.append(Spacer(1, 6))
            
    doc.build(story)
    return filepath
