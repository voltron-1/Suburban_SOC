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

# 6. Command to run the application
CMD ["python", "agent_app.py"]
