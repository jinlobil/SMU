from datetime import datetime,timedelta,timezone

import pytest

from backend.services.settings import SchedulerService

KST=timezone(timedelta(hours=9),'Asia/Seoul')


@pytest.fixture
def daily(tmp_path,monkeypatch):
    monkeypatch.setattr('threading.Thread.start',lambda self:None)
    clock=[datetime(2024,2,10,2,59,tzinfo=KST)]
    monkeypatch.setattr(SchedulerService,'_now',staticmethod(lambda:clock[0]))
    scheduler=SchedulerService(tmp_path,object());calls=[]
    scheduler.firewall_configuration_refresh=lambda:calls.append(clock[0]) or {'firewalls':{'Device':{'refresh_status':'success'}}}
    scheduler.save({'enabled':False,'interval':30,'targets':['firewall_configuration'],
        'firewallConfiguration':{'enabled':True,'time':'03:00'}})
    return scheduler,calls,clock


def test_auto_refresh_daily_clock_not_interval_and_attempt_persisted(daily):
    scheduler,calls,clock=daily
    scheduler._run_cycle();assert calls==[]
    clock[0]=clock[0].replace(hour=3,minute=0)
    scheduler._run_cycle();assert len(calls)==1
    clock[0]=clock[0].replace(hour=18)
    scheduler.state['interval']=120
    scheduler._run_cycle();assert len(calls)==1
    clock[0]+=timedelta(days=1)
    scheduler._run_cycle();assert len(calls)==2
    assert scheduler.get()['firewallConfiguration']['lastAttemptDate']==clock[0].date().isoformat()


def test_failed_auto_attempt_not_repeated_until_next_date(daily):
    scheduler,calls,clock=daily;clock[0]=clock[0].replace(hour=10)
    def fail():calls.append(1);raise TimeoutError()
    scheduler.firewall_configuration_refresh=fail
    scheduler._run_cycle();scheduler._run_cycle()
    assert len(calls)==1
    assert scheduler.get()['targetStatus']['firewall_configuration']['status']=='FAIL'
    clock[0]+=timedelta(days=1);scheduler._run_cycle();assert len(calls)==2


def test_daily_state_survives_restart(daily,tmp_path):
    scheduler,calls,clock=daily;clock[0]=clock[0].replace(hour=10);scheduler._run_cycle()
    restored=SchedulerService(tmp_path,object())
    restored.firewall_configuration_refresh=lambda:calls.append(1)
    restored._run_cycle()
    assert len(calls)==1
    assert restored.get()['firewallConfiguration']['time']=='03:00'


def test_daily_disabled_does_not_collect(daily):
    scheduler,calls,clock=daily;clock[0]=clock[0].replace(hour=10)
    scheduler.save({'targets':['firewall_configuration'],'firewallConfiguration':{'enabled':False,'time':'04:30'}})
    scheduler._run_cycle();assert calls==[]


def test_daily_next_run_kst_and_other_source_interval_preserved(daily,monkeypatch):
    scheduler,calls,clock=daily;clock[0]=clock[0].replace(hour=3,minute=0)
    scheduler.state.update(enabled=True,targets=['aws','firewall_configuration'],interval=120)
    scheduler._next_run_at=clock[0].timestamp()+4000
    original=scheduler._next_run_at
    scheduler._run_cycle(firewall_only=True)
    assert len(calls)==1 and scheduler._next_run_at==original
    next_run=datetime.fromtimestamp(scheduler._daily_due_at(),KST)
    assert next_run.date()==(clock[0]+timedelta(days=1)).date()
    assert (next_run.hour,next_run.minute)==(3,0)


@pytest.mark.parametrize('value',['24:00','03:60','bad','3:00'])
def test_daily_time_validation(daily,value):
    scheduler,_,_=daily
    with pytest.raises(ValueError):scheduler.save({'targets':[],'firewallConfiguration':{'time':value}})


def test_manual_configuration_refresh_bypasses_scheduler_daily_gate(daily,tmp_path):
    from test_firewall_dynamic_packet import service,topology
    scheduler,calls,clock=daily;clock[0]=clock[0].replace(hour=10);scheduler._run_cycle()
    snapshots=topology();current=service(tmp_path,snapshots);collected=[]
    current.configuration.collector=lambda config,refresh:collected.append(config['name']) or snapshots[config['name']]
    current.configuration.refresh();current.configuration.refresh()
    assert len(collected)==2*len(snapshots)
    assert len(calls)==1
