import copy

import pytest

from test_firewall_path_analysis import service, snapshot, rule
from test_firewall_path_layout_browser import path_browser


def test_details_default_collapsed_individual_all_and_new_run_reset(tmp_path,monkeypatch):
    current,_=service(tmp_path,monkeypatch)
    result=current.check('100.1.1.10','203.0.113.10','TCP',443)
    with path_browser(result) as page:
        from playwright.sync_api import expect
        expect(page.locator('details[open]')).to_have_count(0)
        assert page.get_by_text('Matched Rule: allow',exact=True).first.is_visible()
        assert not page.get_by_role('columnheader',name='Rule Name',exact=True).is_visible()
        fold=page.locator('summary').filter(has_text='세부 정책 및 경로 정보 보기').first
        fold.click(); assert page.get_by_role('columnheader',name='Rule Name',exact=True).is_visible()
        fold.click(); assert not page.get_by_role('columnheader',name='Rule Name',exact=True).is_visible()
        page.get_by_role('button',name='모두 펼치기',exact=True).click()
        expect(page.locator('details[open]')).to_have_count(page.locator('details').count())
        page.get_by_role('button',name='모두 접기',exact=True).click()
        expect(page.locator('details[open]')).to_have_count(0)
        page.get_by_role('button',name='모두 펼치기',exact=True).click()
        page.get_by_role('button',name='Path Check',exact=True).click()
        expect(page.locator('details[open]')).to_have_count(0)


@pytest.mark.parametrize('status',['PASS','BLOCK','WARNING','UNKNOWN'])
def test_summary_status_and_block_location_visible_without_expanding(tmp_path,monkeypatch,status):
    current,_=service(tmp_path,monkeypatch)
    result=current.check('100.1.1.10','203.0.113.10','TCP',443)
    result['summary'].update(status=status,blockedAt='Cloud' if status=='BLOCK' else None,primaryReason='fixture primary reason')
    with path_browser(result) as page:
        assert page.locator('.path-summary .result-pill').first.inner_text()==status
        assert page.get_by_text('fixture primary reason',exact=True).is_visible()
        if status=='BLOCK':assert page.get_by_text('Blocked At: Cloud',exact=True).is_visible()
        assert page.locator('.table-wrap:visible').count()==0


@pytest.mark.parametrize('source,destination,mode',[('100.1.1.10','','SOURCE_REACHABILITY'),('','203.0.113.10','DESTINATION_EXPOSURE')])
def test_one_sided_group_summary_and_request_fields(tmp_path,monkeypatch,source,destination,mode):
    data=snapshot();data['rules']=[rule(destination='203.0.113.0/24')]
    current,_=service(tmp_path,monkeypatch,{'Cloud':data})
    result=current.check(source,destination,'TCP',443)
    with path_browser(result) as page:
        assert page.get_by_text(mode,exact=True).is_visible()
        assert page.locator('details[open]').count()==0
        label=result['groups'][0]['label']
        page.locator('summary').filter(has_text=label).first.click()
        assert page.locator('.path-diagram:visible').count()>0
        page.get_by_label('Source IP / CIDR / FQDN',exact=True).fill(source)
        page.get_by_label('Destination IP / CIDR / FQDN',exact=True).fill(destination)
        with page.expect_request('**/api/firewall/path-check') as sent:
            page.get_by_role('button',name='Path Check',exact=True).click()
        assert sent.value.post_data_json['source']==source and sent.value.post_data_json['destination']==destination


def test_nat_and_gateway_are_distinct_path_steps_and_candidates_hidden(tmp_path,monkeypatch):
    current,_=service(tmp_path,monkeypatch)
    result=current.check('100.1.1.10','203.0.113.10','TCP',443)
    result['analysisPath'].insert(0,{'type':'dnat','label':'DNAT','status':'PASS','reason':'Published → Internal','nat':{'Rule Name':'fixture dnat'}})
    result['analysisPath'].append({'type':'snat','label':'SNAT','status':'PASS','reason':'Internal → MASQ','nat':{'Rule Name':'fixture snat'}})
    with path_browser(result) as page:
        assert page.get_by_text('DNAT',exact=True).is_visible() and page.get_by_text('SNAT',exact=True).is_visible()
        assert page.get_by_text('GW',exact=True).is_visible()
        assert page.get_by_text('Destination Route',exact=True).is_visible()
        assert not page.get_by_role('columnheader',name='Rule Name',exact=True).is_visible()


def test_mixed_fqdn_has_collapsed_per_ip_results(tmp_path,monkeypatch):
    import backend.services.firewall_path_check as module
    monkeypatch.setattr(module,'resolve_fqdn',lambda _:['203.0.113.10','198.51.100.10'])
    data=snapshot();data['rules']=[rule(destination='203.0.113.0/24')]
    current,_=service(tmp_path,monkeypatch,{'Cloud':data})
    result=current.check('100.1.1.10','fixture.example.test','TCP',443)
    with path_browser(result) as page:
        assert page.locator('.path-summary .result-pill').first.inner_text()=='WARNING'
        fold=page.locator('summary').filter(has_text='Resolved IP별 결과 (2)')
        assert fold.is_visible() and page.locator('details[open]').count()==0
        fold.click()
        assert page.locator('details[open]').count()==1
        assert len(result['resolvedResults'])==2
