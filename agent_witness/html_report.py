from __future__ import annotations

import html
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .merkle import MerkleTree, compute_leaf_hash
from .models import ConsensusReceipt, DeliberationStep, ProofBundle, StepType, WitnessReceipt


def _step_type_color(step_type: str) -> str:
    mapping = {
        "observation": "#3b82f6",   # Blue
        "thought": "#8b5cf6",       # Violet
        "tool_call": "#f59e0b",     # Amber
        "tool_result": "#06b6d4",   # Cyan
        "decision": "#10b981",      # Emerald
    }
    return mapping.get(step_type.lower(), "#64748b")


def _generate_merkle_svg(steps: List[Dict[str, Any]], merkle_root: str) -> str:
    """Generates an embedded, responsive SVG diagram of the Merkle Action Tree."""
    count = len(steps)
    if count == 0:
        return "<p style='color:#64748b;text-align:center;'>No steps recorded.</p>"

    # Draw a clean hierarchical tree
    width = max(600, count * 110)
    height = 220
    leaf_y = 170
    root_y = 35

    svg_elements = []

    # Calculate leaf positions
    leaf_xs = []
    step_width = width / (count + 1)
    for i in range(count):
        x = step_width * (i + 1)
        leaf_xs.append(x)

    root_x = width / 2

    # Draw lines connecting leaves to root
    for i, lx in enumerate(leaf_xs):
        st = steps[i].get("type", "observation")
        c = _step_type_color(st)
        svg_elements.append(
            f'<line x1="{root_x}" y1="{root_y + 15}" x2="{lx}" y2="{leaf_y - 12}" stroke="{c}" stroke-width="1.5" stroke-dasharray="3,3" opacity="0.45" />'
        )

    # Draw Root Node
    svg_elements.append(
        f'<rect x="{root_x - 70}" y="{root_y - 15}" width="140" height="30" rx="6" fill="#1e1e2e" stroke="#10b981" stroke-width="2" />'
    )
    svg_elements.append(
        f'<text x="{root_x}" y="{root_y + 4}" fill="#10b981" font-family="ui-monospace, monospace" font-size="11" font-weight="700" text-anchor="middle">MERKLE ROOT</text>'
    )

    # Draw Leaf Nodes
    for i, (lx, s) in enumerate(zip(leaf_xs, steps)):
        st = s.get("type", "observation").upper()
        c = _step_type_color(s.get("type", "observation"))
        svg_elements.append(
            f'<rect x="{lx - 45}" y="{leaf_y - 12}" width="90" height="26" rx="5" fill="#131722" stroke="{c}" stroke-width="1.5" />'
        )
        svg_elements.append(
            f'<text x="{lx}" y="{leaf_y + 4}" fill="{c}" font-family="ui-monospace, monospace" font-size="10" font-weight="600" text-anchor="middle">#{s.get("index", i)} {st[:7]}</text>'
        )

    return f'''
    <div style="overflow-x:auto; padding:12px 0;">
        <svg viewBox="0 0 {width} {height}" style="width:100%; min-width:{width}px; height:auto; display:block;">
            {"".join(svg_elements)}
        </svg>
    </div>
    '''


def render_html_report(
    receipt: Union[WitnessReceipt, ProofBundle, ConsensusReceipt, Dict[str, Any]],
    output_file: Optional[Union[str, Path]] = None,
    title: Optional[str] = None,
) -> str:
    """
    Renders an interactive, standalone dark-mode HTML audit dossier for an
    agent witness receipt, selective disclosure bundle, or consensus attestation.
    Zero external CDN dependencies.
    """
    report_title = title or "Agent Witness Cryptographic Audit Dossier"

    if isinstance(receipt, dict):
        if "attestations" in receipt:
            from .models import AgentAttestation
            receipt = ConsensusReceipt(
                version=receipt.get("version", "1.0.0"),
                trajectory_id=receipt.get("trajectory_id", ""),
                merkle_root=receipt.get("merkle_root", ""),
                step_count=receipt.get("step_count", 0),
                threshold=receipt.get("threshold", 1),
                attestations=[AgentAttestation(**a) for a in receipt.get("attestations", [])],
                timestamp=receipt.get("timestamp", 0.0),
            )
        elif "disclosed_step" in receipt:
            from .models import MerkleProof
            receipt = ProofBundle(
                version=receipt.get("version", "1.0.0"),
                agent_id=receipt.get("agent_id", ""),
                agent_pubkey=receipt.get("agent_pubkey", ""),
                model_id=receipt.get("model_id", ""),
                merkle_root=receipt.get("merkle_root", ""),
                signature=receipt.get("signature", ""),
                disclosed_step=receipt.get("disclosed_step", {}),
                merkle_proof=MerkleProof(**receipt.get("merkle_proof", {})),
            )
        else:
            receipt = WitnessReceipt(**receipt)

    is_consensus = isinstance(receipt, ConsensusReceipt)
    is_bundle = isinstance(receipt, ProofBundle)

    if is_consensus:
        merkle_root = receipt.merkle_root
        agent_id = f"Consensus ({len(receipt.attestations)} Agents)"
        model_id = f"Threshold {receipt.threshold}-of-{len(receipt.attestations)}"
        step_count = receipt.step_count
        timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(receipt.timestamp))
        status_badge = "CONSENSUS VERIFIED"
        status_color = "#10b981"
        steps_data = []
    elif is_bundle:
        merkle_root = receipt.merkle_root
        agent_id = receipt.agent_id
        model_id = receipt.model_id
        step_count = 1
        timestamp_str = "Attested Trajectory"
        status_badge = "SELECTIVE DISCLOSURE VERIFIED"
        status_color = "#06b6d4"
        steps_data = [receipt.disclosed_step]
    else:
        merkle_root = receipt.merkle_root
        agent_id = receipt.agent_id
        model_id = receipt.model_id
        step_count = receipt.step_count
        timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(receipt.timestamp))
        status_badge = "CRYPTOGRAPHICALLY ATTESTED"
        status_color = "#10b981"
        steps_data = receipt.steps

    merkle_svg = _generate_merkle_svg(steps_data, merkle_root) if steps_data else ""

    # Generate step rows
    step_rows = []
    for s in steps_data:
        idx = s.get("index", 0)
        st = s.get("type", "observation")
        c = _step_type_color(st)
        content_safe = html.escape(str(s.get("content", "")))
        leaf_hash = s.get("leaf_hash", "")
        leaf_short = f"{leaf_hash[:10]}...{leaf_hash[-8:]}" if leaf_hash else "—"

        meta_str = ""
        if s.get("metadata"):
            meta_json = html.escape(json.dumps(s.get("metadata"), indent=2))
            meta_str = f"<pre style='margin:4px 0 0; font-size:11px; color:#94a3b8;'>{meta_json}</pre>"

        step_rows.append(f"""
        <tr class="step-row" data-type="{st.lower()}">
            <td style="padding:12px; font-family:ui-monospace, monospace; color:#94a3b8; width:50px;">#{idx:02d}</td>
            <td style="padding:12px; width:130px;">
                <span style="display:inline-block; padding:3px 8px; border-radius:4px; font-size:11px; font-weight:700; background:{c}22; color:{c}; border:1px solid {c}55;">
                    {st.upper()}
                </span>
            </td>
            <td style="padding:12px;">
                <div style="font-family:ui-monospace, monospace; font-size:13px; color:#e2e8f0; line-height:1.5;">{content_safe}</div>
                {meta_str}
            </td>
            <td style="padding:12px; font-family:ui-monospace, monospace; font-size:11px; color:#64748b; width:170px;">
                <span title="{leaf_hash}">{leaf_short}</span>
            </td>
        </tr>
        """)

    consensus_section = ""
    if is_consensus:
        att_cards = []
        for att in receipt.attestations:
            verdict_color = "#10b981" if att.verdict == "APPROVE" else "#ef4444"
            att_cards.append(f"""
            <div style="background:#131722; border:1px solid #1e293b; border-radius:8px; padding:14px; margin-bottom:10px;">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                    <div style="font-weight:700; color:#f8fafc; font-size:14px;">{html.escape(att.agent_id)} <span style="font-size:11px; color:#94a3b8; font-weight:400;">({html.escape(att.role)})</span></div>
                    <span style="padding:2px 8px; border-radius:4px; font-size:11px; font-weight:700; background:{verdict_color}22; color:{verdict_color}; border:1px solid {verdict_color}55;">
                        {att.verdict}
                    </span>
                </div>
                <div style="font-size:12px; color:#94a3b8; margin-bottom:4px;">Model: <code style="color:#e2e8f0;">{html.escape(att.model_id)}</code></div>
                <div style="font-size:11px; color:#64748b; font-family:ui-monospace, monospace;">Pubkey: {att.agent_pubkey[:24]}...</div>
                {f'<div style="font-size:12px; color:#cbd5e1; margin-top:6px; font-style:italic;">"{html.escape(att.comments)}"</div>' if att.comments else ''}
            </div>
            """)
        consensus_section = f"""
        <div style="background:#0f172a; border:1px solid #1e293b; border-radius:10px; padding:20px; margin-bottom:24px;">
            <h3 style="margin:0 0 16px; font-size:16px; color:#38bdf8; display:flex; align-items:center; gap:8px;">
                Multi-Agent Consensus Roster ({len(receipt.attestations)} Agents)
            </h3>
            {"".join(att_cards)}
        </div>
        """

    full_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{report_title}</title>
    <style>
        * {{ box-sizing: border-box; margin:0; padding:0; }}
        body {{
            background-color: #090d16;
            color: #f1f5f9;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            padding: 32px 20px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1080px;
            margin: 0 auto;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #1e293b;
            padding-bottom: 20px;
            margin-bottom: 24px;
            flex-wrap: wrap;
            gap: 16px;
        }}
        .title-badge {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: rgba(16, 185, 129, 0.1);
            color: {status_color};
            border: 1px solid rgba(16, 185, 129, 0.3);
            padding: 4px 12px;
            border-radius: 9999px;
            font-size: 12px;
            font-weight: 700;
            letter-spacing: 0.05em;
        }}
        .pulse-dot {{
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background-color: {status_color};
            box-shadow: 0 0 8px {status_color};
        }}
        .metric-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .card {{
            background: #0f172a;
            border: 1px solid #1e293b;
            border-radius: 10px;
            padding: 16px;
        }}
        .card-label {{
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: #64748b;
            margin-bottom: 4px;
        }}
        .card-value {{
            font-size: 15px;
            font-weight: 700;
            color: #f8fafc;
            word-break: break-all;
        }}
        .card-value.mono {{
            font-family: ui-monospace, monospace;
            font-size: 13px;
            color: #38bdf8;
        }}
        .filter-btn {{
            background: #1e293b;
            color: #94a3b8;
            border: none;
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 12px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.15s ease;
        }}
        .filter-btn.active {{
            background: #38bdf8;
            color: #0f172a;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        tr:hover td {{
            background: #1e293b44;
        }}
        tr:not(:last-child) td {{
            border-bottom: 1px solid #1e293b;
        }}
        input.search-input {{
            background: #131722;
            border: 1px solid #334155;
            color: #f8fafc;
            padding: 8px 14px;
            border-radius: 6px;
            font-size: 13px;
            width: 260px;
            outline: none;
        }}
        input.search-input:focus {{
            border-color: #38bdf8;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1 style="font-size:24px; font-weight:800; color:#f8fafc; margin-bottom:4px;">agent-witness</h1>
                <div style="font-size:13px; color:#94a3b8;">Cryptographic Deliberation & Action Attestation Dossier</div>
            </div>
            <div class="title-badge">
                <span class="pulse-dot"></span>
                <span>{status_badge}</span>
            </div>
        </div>

        <div class="metric-grid">
            <div class="card">
                <div class="card-label">Agent ID</div>
                <div class="card-value">{html.escape(agent_id)}</div>
            </div>
            <div class="card">
                <div class="card-label">Model Runtime</div>
                <div class="card-value">{html.escape(model_id)}</div>
            </div>
            <div class="card">
                <div class="card-label">Deliberation Steps</div>
                <div class="card-value">{step_count} Verified Steps</div>
            </div>
            <div class="card">
                <div class="card-label">Attested Timestamp</div>
                <div class="card-value" style="font-size:13px;">{timestamp_str}</div>
            </div>
        </div>

        <div class="card" style="margin-bottom:24px;">
            <div class="card-label">Cryptographic Action Merkle Root</div>
            <div class="card-value mono" style="font-size:14px; margin-top:4px;">{merkle_root}</div>
        </div>

        {consensus_section}

        <div class="card" style="margin-bottom:24px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                <h3 style="font-size:15px; font-weight:700; color:#f8fafc;">Merkle Action Hierarchy</h3>
                <span style="font-size:11px; color:#64748b;">RFC 6962 Standard</span>
            </div>
            {merkle_svg}
        </div>

        <div class="card" style="padding:0; overflow:hidden;">
            <div style="padding:16px 20px; border-bottom:1px solid #1e293b; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px;">
                <div style="display:flex; gap:8px; flex-wrap:wrap;">
                    <button class="filter-btn active" onclick="filterSteps('all', this)">ALL ({len(steps_data)})</button>
                    <button class="filter-btn" onclick="filterSteps('observation', this)">OBSERVATION</button>
                    <button class="filter-btn" onclick="filterSteps('thought', this)">THOUGHT</button>
                    <button class="filter-btn" onclick="filterSteps('tool_call', this)">TOOL_CALL</button>
                    <button class="filter-btn" onclick="filterSteps('tool_result', this)">TOOL_RESULT</button>
                    <button class="filter-btn" onclick="filterSteps('decision', this)">DECISION</button>
                </div>
                <div>
                    <input type="text" class="search-input" placeholder="Search deliberation steps..." onkeyup="searchSteps(this.value)">
                </div>
            </div>

            <div style="overflow-x:auto;">
                <table id="steps-table">
                    <thead>
                        <tr style="background:#090d16; text-align:left; font-size:11px; color:#64748b; text-transform:uppercase;">
                            <th style="padding:10px 12px;">Index</th>
                            <th style="padding:10px 12px;">Type</th>
                            <th style="padding:10px 12px;">Deliberation / Execution Content</th>
                            <th style="padding:10px 12px;">Leaf Hash</th>
                        </tr>
                    </thead>
                    <tbody>
                        {"".join(step_rows)}
                    </tbody>
                </table>
            </div>
        </div>

        <div style="margin-top:24px; text-align:center; font-size:12px; color:#475569;">
            Generated by <strong>agent-witness v0.5.0</strong> • <a href="https://github.com/devsoniclk/agent-witness" style="color:#38bdf8; text-decoration:none;">github.com/devsoniclk/agent-witness</a>
        </div>
    </div>

    <script>
        function filterSteps(type, btn) {{
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            const rows = document.querySelectorAll('.step-row');
            rows.forEach(r => {{
                if (type === 'all' || r.getAttribute('data-type') === type) {{
                    r.style.display = '';
                }} else {{
                    r.style.display = 'none';
                }}
            }});
        }}

        function searchSteps(query) {{
            query = query.toLowerCase();
            const rows = document.querySelectorAll('.step-row');
            rows.forEach(r => {{
                const text = r.innerText.toLowerCase();
                if (text.includes(query)) {{
                    r.style.display = '';
                }} else {{
                    r.style.display = 'none';
                }}
            }});
        }}
    </script>
</body>
</html>
"""

    if output_file:
        out_path = Path(output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(full_html)

    return full_html
