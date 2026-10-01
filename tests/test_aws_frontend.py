from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_aws_asset_route_reuses_existing_asset_patterns():
    app = (ROOT / "frontend/src/App.tsx").read_text(encoding="utf-8")
    page = (ROOT / "frontend/src/pages/AwsAssetPage.tsx").read_text(encoding="utf-8")
    assert '{ label: "AWS", route: "/assets/aws" }' in app
    assert '<Route path="/assets/aws" element={<AwsAssetPage />} />' in app
    for class_name in ("summary-grid", "panel", "panel-head", "search-box", "table-wrap", "pagination", "detail-modal", "integration-tags"):
        assert class_name in page
    assert page.count("<th>") == 8
    assert 'target="aws"' in page


def test_aws_is_present_in_raw_cache_and_scheduler_without_index_button():
    page = (ROOT / "frontend/src/pages/ConfigPage.tsx").read_text(encoding="utf-8")
    assert 'aws:"AWS Raw Cache"' in page
    assert '["aws","AWS"]' in page
    assert 'refresh("aws")' in page
    assert "AWS 전체 캐시 인덱싱" not in page and "AWS Index" not in page


def test_fetcher_routes_aws_without_requesting_an_aws_index():
    fetcher = (ROOT / "system_monitor/fetcher.py").read_text(encoding="utf-8")
    assert 'target == "aws"' in fetcher and "refresh_aws(progress)" in fetcher
    assert 'any(target != "aws" for target in targets)' in fetcher
