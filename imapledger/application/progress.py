from __future__ import annotations

from pathlib import Path

from ..config import Settings
from ..progress_store import MessageResult, ProgressRun, ProgressStore, account_identity_key, default_progress_path


class ProgressOperation:
    """Account-scoped queries and reset for resumable routing progress."""

    def __init__(self, settings: Settings, path: Path | None = None) -> None:
        self.path = path or default_progress_path()
        self._account_key = account_identity_key(settings)
        self._store = ProgressStore(self.path)

    def list_runs(self, *, folder: str | None = None, limit: int = 100) -> tuple[ProgressRun, ...]:
        return self._store.list_runs(account_key=self._account_key, source_folder=folder, limit=limit)

    def latest_run(self, folder: str) -> ProgressRun | None:
        runs = self.list_runs(folder=folder, limit=1000)
        return runs[0] if runs else None

    def latest_run_with_errors(self, folder: str) -> ProgressRun | None:
        return next((run for run in self.list_runs(folder=folder, limit=1000) if run.error_count), None)

    def errors(self, run_id: str, *, limit: int | None = None) -> tuple[MessageResult, ...]:
        return self._store.errors(run_id, limit=limit)

    def reset_folder(self, folder: str) -> int:
        return self._store.reset_folder(self._account_key, folder)
