# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
# routes.py — backward-compat shim; all logic is now in app/backend/routers/
from fastapi import APIRouter
from .routers.upload import router as _upload_router
from .routers.jobs import router as _jobs_router
from .routers.gates import router as _gates_router
from .routers.batch import router as _batch_router
from .routers.logs import router as _logs_router
from .routers.exports import router as _exports_router
from .routers.misc import router as _misc_router
from .routers.patterns import router as _patterns_router

# Re-export shared state so main.py and watcher.py can still import them directly:
#   from backend.routes import _active_tasks
#   from backend.routes import recover_batch_jobs
#   from backend.routes import _batch_semaphore
from .routers._helpers import _active_tasks, _progress_queues, _batch_semaphore  # noqa: F401
from .routers.batch import recover_batch_jobs  # noqa: F401

router = APIRouter(prefix="/api")
router.include_router(_upload_router)
router.include_router(_jobs_router)
router.include_router(_gates_router)
router.include_router(_batch_router)
router.include_router(_logs_router)
router.include_router(_exports_router)
router.include_router(_misc_router)
router.include_router(_patterns_router)
