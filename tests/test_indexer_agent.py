from system_monitor.indexer import IndexerAgent


def test_indexer_jobs_are_persistent_and_coalesced(tmp_path):
    agent = IndexerAgent(tmp_path)

    first = agent.submit()
    second = agent.submit()
    restored = IndexerAgent(tmp_path).get(first["id"])

    assert first["id"] == second["id"]
    assert restored is not None
    assert restored["status"] == "queued"


def test_interrupted_indexer_job_is_requeued_on_start(tmp_path):
    agent = IndexerAgent(tmp_path)
    job = agent.submit()
    agent._update(job["id"], status="running", message="작업 중", started_at=agent._now())

    recovered = IndexerAgent(tmp_path).get(job["id"])

    assert recovered is not None
    assert recovered["status"] == "queued"
    assert "복구" in recovered["message"]
