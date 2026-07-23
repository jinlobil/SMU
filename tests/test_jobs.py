import threading

from backend.services.jobs import JobManager


def test_job_manager_completes_and_reports_result() -> None:
    manager = JobManager()
    finished = threading.Event()

    def task(progress):
        progress("working")
        finished.set()
        return {"rows": 3}

    created = manager.create("test", task)
    assert finished.wait(2)
    for _ in range(100):
        job = manager.get(created["id"])
        if job and job["status"] == "completed":
            break
        finished.wait(0.01)

    assert job["status"] == "completed"
    assert job["result"] == {"rows": 3}


def test_job_manager_persists_failure_details() -> None:
    manager = JobManager()

    def task(_progress):
        raise RuntimeError("expected failure")

    created = manager.create("test-failure", task)
    for _ in range(100):
        job = manager.get(created["id"])
        if job and job["status"] == "failed":
            break
        threading.Event().wait(0.01)

    assert job["status"] == "failed"
    assert "expected failure" in job["error"]["message"]
