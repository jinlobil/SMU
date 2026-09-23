import logging
import threading
import traceback
import uuid
from datetime import datetime, timezone
from typing import Callable


log = logging.getLogger("smu.jobs")
job_events = logging.getLogger("smu.job.events")


class JobManager:
    def __init__(self):
        self._jobs: dict[str, dict] = {}
        self._lock = threading.Lock()

    def create(self, job_type: str, task: Callable[[Callable[[str], None]], dict]) -> dict:
        job_id = str(uuid.uuid4())
        job = {"id": job_id, "type": job_type, "status": "queued", "message": "대기 중", "result": None, "error": None, "createdAt": self._now(), "finishedAt": None}
        with self._lock:
            self._jobs[job_id] = job
        threading.Thread(target=self._run, args=(job_id, task), daemon=True, name=f"smu-job-{job_id[:8]}").start()
        return dict(job)

    def get(self, job_id: str) -> dict | None:
        with self._lock:
            job = self._jobs.get(job_id)
            return dict(job) if job else None

    def update_message(self, job_id: str, message: str) -> None:
        with self._lock:
            self._jobs[job_id]["message"] = message

    def _run(self, job_id: str, task: Callable[[Callable[[str], None]], dict]) -> None:
        job_events.info("Job started job_id=%s type=%s", job_id, self._jobs[job_id]["type"])
        with self._lock:
            self._jobs[job_id]["status"] = "running"
            self._jobs[job_id]["message"] = "작업 시작"
        try:
            result = task(lambda message: self.update_message(job_id, message))
            with self._lock:
                self._jobs[job_id].update(status="completed", message="완료", result=result, finishedAt=self._now())
            job_events.info("Job completed job_id=%s type=%s", job_id, self._jobs[job_id]["type"])
        except Exception as exc:
            log.exception("Background job failed job_id=%s type=%s", job_id, self._jobs[job_id]["type"])
            with self._lock:
                self._jobs[job_id].update(status="failed", message="실패", error={"message": f"{type(exc).__name__}: {exc}", "traceback": traceback.format_exc()}, finishedAt=self._now())
            job_events.warning("Job failed job_id=%s type=%s", job_id, self._jobs[job_id]["type"])

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()
