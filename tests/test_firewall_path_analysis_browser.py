"""Browser acceptance tests for conclusions, progress and concise evidence only."""
import copy

import pytest

from test_firewall_path_analysis import service, snapshot, rule
from test_firewall_path_layout_browser import path_browser


def test_no_raw_tables_json_or_expand_all_and_evidence_resets(tmp_path,monkeypatch):
    current,_=service(tmp_path,monkeypatch)
    result=current.check('100.1.1.10','203.0.113.10','TCP',443)
    with path_browser(result) as page:
        from playwright.sync_api import expect
        assert page.locator('table, pre').count()==0
        assert page.get_by_role('button',name='모두 펼치기').count()==0
        assert page.get_by_role('button',name='모두 접기').count()==0
        assert page.get_by_text('기존 정책 및 AWS SG 상세',exact=True).count()==0
        assert page.locator('details[open]').count()==0
        page.get_by_text('판정 근거 보기',exact=True).first.click()
        assert page.locator('details[open]').count()==1
        assert page.locator('.path-evidence').first.is_visible()
        assert page.locator('table, pre').count()==0
        page.get_by_role('button',name='분석',exact=True).click()
        expect(page.locator('details[open]')).to_have_count(0)


@pytest.mark.parametrize('width',[1440,1024,768,390])
def test_progress_vertical_stepper_responsive_no_horizontal_overflow(tmp_path,monkeypatch,width):
    current,_=service(tmp_path,monkeypatch)
    result=current.check('100.1.1.10','203.0.113.10','TCP',443)
    with path_browser(result,width) as page:
        assert page.get_by_role('navigation',name='패킷 이동 경로').is_visible()
        assert page.locator('.path-progress li[data-status="PASS"]').count()>0
        cards=page.locator('.path-vertical-step article')
        boxes=[cards.nth(i).bounding_box() for i in range(cards.count())]
        assert all(a['y']+a['height'] <= b['y']+1 for a,b in zip(boxes,boxes[1:]))
        assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
        for summary in page.locator('.path-vertical summary').all():summary.click()
        assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
        assert page.locator('table, pre').count()==0


def test_block_summary_and_progress_downstream_are_inactive(tmp_path,monkeypatch):
    data=snapshot();data['rules']=[rule('First Drop',action='Drop')];data['routes']=[]
    current,_=service(tmp_path,monkeypatch,{'Cloud':data})
    result=current.check('100.1.1.10','203.0.113.10','TCP',None)
    with path_browser(result) as page:
        assert page.locator('.path-summary [data-status="BLOCK"]').count()==1
        assert page.get_by_text('Cloud에서 차단',exact=True).is_visible()
        assert page.locator('.path-summary').get_by_text('Matched Rule: First Drop · Action: Drop',exact=True).is_visible()
        assert page.locator('.path-progress li[data-status="BLOCK"]').count()==1
        assert page.locator('.path-progress li[data-status="NOT_REACHED"]').count()>0
        assert page.locator('.path-progress li[data-status="NOT_REACHED"][data-link-active="true"]').count()==0
        assert page.locator('.path-vertical-step[data-status="NOT_REACHED"]').count()>0


@pytest.mark.parametrize('source,destination,mode',[('100.1.1.10','','SOURCE_REACHABILITY'),('','203.0.113.10','DESTINATION_EXPOSURE')])
def test_one_sided_summary_selection_displays_only_selected_path(tmp_path,monkeypatch,source,destination,mode):
    data=snapshot();data['rules']=[rule(destination='203.0.113.0/24')]
    current,_=service(tmp_path,monkeypatch,{'Cloud':data})
    result=current.check(source,destination,'TCP',443)
    with path_browser(result,390) as page:
        assert page.locator(f'[data-mode={mode}]').is_visible()
        assert page.locator('.path-progress').count()==0
        page.get_by_role('button',name='경로 보기:',exact=False).first.click()
        assert page.locator('.mini-path').count()>0
        assert page.locator('.path-vertical').count()==1
        assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
        page.get_by_label('Source IP / CIDR / FQDN',exact=True).fill(source)
        page.get_by_label('Destination IP / CIDR / FQDN',exact=True).fill(destination)
        with page.expect_request('**/api/firewall/path-check') as sent:
            page.get_by_role('button',name='분석',exact=True).click()
        assert sent.value.post_data_json['source']==source and sent.value.post_data_json['destination']==destination


def test_service_scope_selection_switches_block_and_pass_path(tmp_path,monkeypatch):
    from test_firewall_path_decisions import svc
    data=snapshot();data['rules']=[svc(rule('HTTPS'),443),rule('Drop rest',action='Drop',order=2)]
    current,_=service(tmp_path,monkeypatch,{'Cloud':data})
    result=current.check('100.1.1.10','203.0.113.10','TCP',None)
    with path_browser(result) as page:
        assert page.locator('.path-summary [data-status="WARNING"]').count()==1
        page.get_by_label('서비스 범위',exact=True).select_option('1')
        assert page.locator('.path-summary [data-status="PASS"]').count()==1
        assert page.locator('.path-progress li[data-status="BLOCK"]').count()==0
        page.get_by_label('서비스 범위',exact=True).select_option('0')
        assert page.locator('.path-summary [data-status="BLOCK"]').count()==1
        assert page.locator('.path-progress li[data-status="NOT_REACHED"]').count()>0


def test_mixed_fqdn_selects_one_resolved_path(tmp_path,monkeypatch):
    import backend.services.firewall_path_check as module
    monkeypatch.setattr(module,'resolve_fqdn',lambda _:['203.0.113.10','198.51.100.10'])
    data=snapshot();data['rules']=[rule(destination='203.0.113.0/24')]
    data['resolvedFqdnAddresses']={'fixture.example.test':['203.0.113.10','198.51.100.10']}
    current,_=service(tmp_path,monkeypatch,{'Cloud':data})
    result=current.check('100.1.1.10','fixture.example.test','TCP',443)
    with path_browser(result) as page:
        assert page.locator('.path-summary [data-status="WARNING"]').count()==1
        page.get_by_role('button',name='100.1.1.10/32 → 198.51.100.10',exact=False).click()
        assert page.locator('.path-summary [data-status="BLOCK"]').count()==1
        assert page.locator('.path-vertical').count()==1


def test_network_scope_selection_switches_reached_and_blocked_path(tmp_path,monkeypatch):
    data=snapshot();data['rules']=[rule(source='100.1.1.0/25')]
    current,_=service(tmp_path,monkeypatch,{'Cloud':data})
    result=current.check('100.1.1.0/24','203.0.113.10','TCP',443)
    with path_browser(result,390) as page:
        assert page.locator('.path-summary [data-status="WARNING"]').count()==1
        page.get_by_label('Network 범위',exact=True).select_option('0')
        assert page.locator('.path-summary [data-status="PASS"]').count()==1
        page.get_by_label('Network 범위',exact=True).select_option('1')
        assert page.locator('.path-summary [data-status="BLOCK"]').count()==1
        assert page.locator('.path-progress li[data-status="NOT_REACHED"]').count()>0
        assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
