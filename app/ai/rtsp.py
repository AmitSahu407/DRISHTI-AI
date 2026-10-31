"""RTSP worker boundary. Never open/block on RTSP streams in FastAPI request handlers."""
class RTSPStreamProcessor:
    def __init__(self, camera_id: int, stream_url: str):
        self.camera_id = camera_id
        self.stream_url = stream_url

    async def start(self):
        # TODO: use a supervised worker + OpenCV/FFmpeg/GStreamer with reconnect/backoff.
        raise NotImplementedError("Connect an RTSP ingestion worker before enabling live processing")
