# SMU local web application

The web application is a local-only replacement shell for the PyQt UI. Existing
JSON/JSONL caches, SQLite read models, theme files, and Python business logic are
reused. The legacy UI remains available during functional-parity migration.

## Development

```bash
python -m pip install -r requirements-web.txt
cd web_frontend && npm install && npm run build && cd ..
python run_web.py
```

Open `http://127.0.0.1:8000`. The server deliberately binds only to the loopback
interface. Interactive API documentation is available at `/api/docs`.

## Architecture

* `web_backend/`: FastAPI facade around reusable Python storage and services.
* `web_frontend/`: React/TypeScript user interface with motion and responsive data views.
* `run_web.py`: single local launcher that opens the default browser.
* `uimain_window.py`: retained as the functional reference while parity is verified.

The API performs filtering and pagination before returning records so large local
datasets do not block browser rendering. Long-running indexing is represented as
a background job and can be polled without freezing the interface.
