"""interfaces.gui — the Coreline self-hosted web console.

A local Streamlit web app over the same ``interfaces.cli.workspace.IncidentWorkspace``
domain layer the CLI drives (ADR-0002 §4: one core, many front-ends). Point-and-click
incident response in a browser tab — no commands, no flags. Uses the on-disk incident
store with the CLI, so incidents declared in either surface appear in the other.

Launch:  ./run_gui.sh   (boots streamlit on http://localhost:8501 and opens a browser)
"""
