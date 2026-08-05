from system_monitor.indexer import IndexerAgent


def test_indexer_jobs_are_persistent_and_coalesced(tmp_path):
    agent = IndexerAgent(tmp_path)

    first = agent.submit()
    second = agent.submit()
    restored = IndexerAgent(tmp_path).get(first["id"])

    assert first["id"] == second["id"]
    assert restored is not None
    assert restored["status"] == "queued"
    assert restored["type"] == "smart-indexes"


def test_interrupted_indexer_job_is_requeued_on_start(tmp_path):
    agent = IndexerAgent(tmp_path)
    job = agent.submit()
    agent._update(job["id"], status="running", message="작업 중", started_at=agent._now())

    recovered = IndexerAgent(tmp_path).get(job["id"])

    assert recovered is not None
    assert recovered["status"] == "queued"
    assert "복구" in recovered["message"]


def test_incremental_job_persists_requested_date_range(tmp_path):
    agent = IndexerAgent(tmp_path)

    job = agent.submit("2026-07-30", "2026-07-31")

    with agent._connect() as db:
        row = db.execute("SELECT type,range_start,range_end FROM jobs WHERE id=?", (job["id"],)).fetchone()
    assert tuple(row) == ("incremental-indexes", "2026-07-30", "2026-07-31")


def test_force_full_job_is_explicit_and_separate_from_smart_job(tmp_path):
    agent = IndexerAgent(tmp_path)

    smart = agent.submit()
    full = agent.submit(force_full=True)

    assert smart["type"] == "smart-indexes"
    assert full["type"] == "rebuild-all-indexes"
    assert smart["id"] != full["id"]


def test_indexer_accepts_fetch_job_incremental_source(tmp_path):
    agent = IndexerAgent(tmp_path)

    job = agent.submit(source_fetch_job="fetch-123")

    assert job["type"] == "fetch-incremental-indexes"
    assert job["sourceFetchJob"] == "fetch-123"
