import copy
import pytest

from test_firewall_path_analysis import service,snapshot,rule
from test_firewall_path_layout_browser import path_browser


def cards(tmp_path,monkeypatch):
    data=snapshot();data['rules']=[rule('first',destination='203.0.113.0/24')]
    current,_=service(tmp_path,monkeypatch,{'Cloud':data})
    result=current.check('100.1.1.10','','TCP',443)
    group=result['groups'][0]
    result['groups']=[]
    for label,status in [('Allowed Network','PASS'),('Blocked Network','BLOCK'),('DNS Scope','UNKNOWN')]:
        item=copy.deepcopy(group);item.update(label=label,status=status)
        item['results'][0]['summary']['status']=status
        if status=='BLOCK':
            item['results'][0]['summary'].update(blockedAt='Cloud',matchedRule='Fixture Drop',action='Drop',primaryReason='Fixture Rule Block')
            steps=item['results'][0]['analysisPath'];steps[0]['status']='BLOCK'
            for step in steps[1:]:step['status']='NOT_REACHED'
            nodes=item['results'][0]['progress']['nodes'];nodes[1]['status']='BLOCK'
            for node in nodes[2:]:node['status']='NOT_REACHED'
        item['miniPath']=copy.deepcopy(item['results'][0]['progress'])
        result['groups'].append(item)
    return result


@pytest.mark.parametrize('width',[1440,1024,390])
def test_reference_cards_filters_single_accordion_mini_path_and_side_panel(tmp_path,monkeypatch,width):
    result=cards(tmp_path,monkeypatch)
    with path_browser(result,width) as page:
        assert page.locator('.path-result-card').count()==3
        if width==1440:
            positions=[page.get_by_role('button',name=name,exact=True).bounding_box()['y'] for name in ['전체 3','허용 1','차단 1','주의 1']]
            assert max(positions)-min(positions)<2
        assert page.locator('.mini-path').count()==3
        assert page.locator('.path-card-expanded').count()==0
        page.get_by_role('button',name='경로 보기: Allowed Network',exact=True).click()
        assert page.locator('.path-card-expanded').count()==1
        page.get_by_role('button',name='경로 보기: Blocked Network',exact=True).click()
        assert page.locator('.path-card-expanded').count()==1
        assert page.get_by_role('button',name='경로 보기: Allowed Network',exact=True).get_attribute('aria-expanded')=='false'
        assert page.get_by_role('complementary',name='최종 판단').is_visible()
        assert page.get_by_text('Fixture Rule Block',exact=True).count()>0
        assert page.locator('.mini-path li[data-status="NOT_REACHED"][data-link-active="true"]').count()==0
        assert page.locator('table, pre').count()==0
        assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
        page.get_by_role('button',name='차단 1',exact=True).click()
        assert page.locator('.path-result-card').count()==1
        page.get_by_role('button',name='주의 1',exact=True).click()
        assert page.get_by_role('button',name='경로 보기: DNS Scope',exact=True).is_visible()
        page.get_by_role('button',name='허용 1',exact=True).click()
        assert page.get_by_role('button',name='경로 보기: Allowed Network',exact=True).is_visible()
        page.get_by_role('button',name='전체 3',exact=True).click()
        assert page.locator('.path-result-card').count()==3


def test_refresh_is_separate_and_search_stays_available_while_refreshing(tmp_path,monkeypatch):
    result=cards(tmp_path,monkeypatch)
    with path_browser(result) as page:
        from playwright.sync_api import expect
        active={'value':True};posts=[]
        def configuration(route):
            if route.request.method=='POST':posts.append(1)
            route.fulfill(json={'success':True,'data':{'running':active['value']}})
        page.route('**/api/firewall/configuration/status',configuration)
        page.route('**/api/firewall/configuration/refresh',configuration)
        page.get_by_role('button',name='최신 정보 다시 조회',exact=True).click()
        expect(page.get_by_role('button',name='최신 정보 조회 중...',exact=True)).to_be_disabled()
        expect(page.get_by_role('button',name='분석',exact=True)).to_be_enabled()
        page.get_by_label('Source IP / CIDR / FQDN',exact=True).fill('100.1.1.11')
        with page.expect_request('**/api/firewall/path-check') as sent:
            page.get_by_role('button',name='분석',exact=True).click()
        assert sent.value.post_data_json['refresh'] is False
        active['value']=False
        with page.expect_request('**/api/firewall/path-check') as repeated:
            expect(page.get_by_role('button',name='최신 정보 다시 조회',exact=True)).to_be_enabled()
        assert repeated.value.post_data_json['source']=='100.1.1.11'
        assert len(posts)==1


def test_both_empty_inputs_do_not_start_analysis(tmp_path,monkeypatch):
    result=cards(tmp_path,monkeypatch)
    with path_browser(result) as page:
        page.get_by_label('Source IP / CIDR / FQDN',exact=True).fill('')
        page.get_by_label('Destination IP / CIDR / FQDN',exact=True).fill('')
        assert page.get_by_role('button',name='분석',exact=True).is_disabled()
        assert page.get_by_role('button',name='최신 정보 다시 조회',exact=True).is_enabled()


def test_source_only_mixed_fqdn_card_exposes_per_ip_decisions(tmp_path,monkeypatch):
    data=snapshot();data['rules']=[rule('IP Drop',destination='198.51.100.0/24',action='Drop'),rule('Domain Allow',destination='Domain Group',order=2)]
    data['rules'][1].update({'Destination Resolved':'203.0.113.10\n198.51.100.10','_Destination FQDNs':['target.example.test']})
    data['objects']={'Domain Group':'203.0.113.10\n198.51.100.10'}
    data['fqdnObjects']={'Domain Group':['target.example.test']}
    data['resolvedFqdnAddresses']={'target.example.test':['203.0.113.10','198.51.100.10']}
    current,_=service(tmp_path,monkeypatch,{'Cloud':data})
    result=current.check('100.1.1.10','','TCP',443)
    with path_browser(result) as page:
        page.get_by_role('button',name='경로 보기: Domain Group',exact=True).click()
        page.get_by_label('Resolve IP',exact=True).select_option('1')
        assert page.locator('.path-decision-panel [data-status="BLOCK"]').count()==1
        page.get_by_label('Resolve IP',exact=True).select_option('0')
        assert page.locator('.path-decision-panel [data-status="PASS"]').count()==1
        assert page.locator('table, pre').count()==0
