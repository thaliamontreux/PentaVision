from app import create_app
from app.recording_service import start_recording_service
from app.stream_service import start_stream_service


app = create_app()


if __name__ == "__main__":
    # For local development, also start background services in this process.
    start_recording_service(app)
    start_stream_service(app)
    # Disable the Werkzeug reloader here to avoid stdin/tty issues in some
    # IDE/terminal environments while still keeping debug features enabled.
    app.run(debug=True, use_reloader=False)
