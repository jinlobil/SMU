from pathlib import Path


def test_layout_is_hidden_but_route_is_preserved() -> None:
    app = (Path(__file__).resolve().parents[1] / "frontend/src/App.tsx").read_text(encoding="utf-8")
    assert '{ label: "Lab", route: "/lab/machine-learning" }' in app
    assert 'Lab: [{ label: "Machine Learning", route: "/lab/machine-learning" }]' in app
    assert '<Route path="/lab/layout" element={<LayoutPage />} />' in app
    assert 'label: "Layout - User"' not in app
