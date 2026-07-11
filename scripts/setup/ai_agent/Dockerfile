# 1. Use a lightweight official Python image
FROM python:3.11-slim

# 2. Set the working directory inside the container
WORKDIR /app

# 2b. Native libraries required by WeasyPrint (weekly_ciso_report.py -> PDF).
#     Without these the agent crashes on import with
#     "cannot load library 'libgobject-2.0-0'". libglib2.0-0 provides gobject;
#     pango/cairo/gdk-pixbuf provide the rendering stack.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libglib2.0-0 \
        libpango-1.0-0 \
        libpangocairo-1.0-0 \
        libgdk-pixbuf-2.0-0 \
        libcairo2 \
        libffi8 \
        shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

# 3. Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 4. Copy the rest of your agent's code into the container
COPY . .

# 4b. Drop root (audit P1-4): run as a dedicated non-root user. The agent writes its
#     approval queue under /app and renders PDFs to /tmp, so give the user ownership
#     of /app. A code-exec bug in the webhook listener then yields an unprivileged
#     user, not root.
RUN useradd --create-home --uid 10001 appuser && chown -R appuser:appuser /app
USER appuser

# 5. Expose port 5000 for Kibana webhooks
EXPOSE 5000

# 6. Command to run the application (audit #172, SA-11/SC-5): gunicorn instead
#    of Werkzeug's single-threaded dev server. Deliberately --workers 1 (a
#    single PROCESS) rather than the multi-process "-w 2" a naive prod-WSGI
#    swap would use: agent_app.py's replay-nonce cache (_seen_sigs) and its
#    approval-queue writer (_queue_lock) are threading.Lock-guarded in-process
#    state, not cross-process-safe — two worker processes would each keep an
#    independent nonce cache, so a replayed HMAC signature could land on the
#    worker that never saw the original and be silently re-accepted.
#    --worker-class gthread --threads 4 keeps a single process (existing locks
#    stay correct) while still adding real concurrency over the dev server.
CMD ["gunicorn", "--worker-class", "gthread", "--workers", "1", "--threads", "4", \
     "--bind", "0.0.0.0:5000", "--access-logfile", "-", "--error-logfile", "-", \
     "agent_app:app"]
