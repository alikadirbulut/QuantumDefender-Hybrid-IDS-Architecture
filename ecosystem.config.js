module.exports = {
  apps: [
    {
      name: "quantum-defender",
      script: "gunicorn",
      interpreter: "none",
      args: [
        "--worker-class", "eventlet",
        "--workers",      "1",
        "--bind",         "127.0.0.1:5000",
        "--timeout",      "120",
        "--keep-alive",   "5",
        "--log-level",    "info",
        "--access-logfile", "logs/access.log",
        "--error-logfile",  "logs/error.log",
        "mock_cloud:app"
      ],
      cwd: "/home/akedon/quantum",   // ← change to your actual path
      env: {
        FLASK_ENV:           "production",
        QD_API_KEY:          "change-me-to-a-strong-secret",
        QD_HOST:             "127.0.0.1",
        QD_PORT:             "5000",
        QD_DB_PATH:          "cloud_store.db",
        QD_ONNX_MODEL:       "lite_model.onnx",
        QD_ALERT_THRESHOLD:  "0.85",
      },
      autorestart:    true,
      watch:          false,
      max_memory_restart: "512M",
      log_date_format: "YYYY-MM-DD HH:mm:ss",
    }
  ]
};
