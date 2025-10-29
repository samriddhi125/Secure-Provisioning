from pydantic import BaseModel, Field
from typing import Optional, Literal


class MovieDetails(BaseModel):
    """Movie information extracted from user request."""
    movie_name: Optional[str] = Field(default="")
    language: Optional[str] = Field(default="")


class VideoQuality(BaseModel):
    """Video quality parameters."""
    resolution: Optional[Literal["480p", "720p", "1080p", "1440p", "2160p", "4320p"]] = Field(default="2160p")
    frame_rate: Optional[Literal["24fps", "30fps", "60fps", "120fps"]] = Field(default=None)


class NetworkRequirements(BaseModel):
    """Network-related requirements."""
    max_latency: Optional[str] = Field(default="50ms")
    adaptive_streaming: Optional[bool] = Field(default=True)


class AudioQuality(BaseModel):
    """Audio quality parameters."""
    codec: Optional[Literal["AAC", "MP3", "FLAC", "Opus", "AC3", "DTS"]] = Field(default=None)


class Reliability(BaseModel):
    """Service reliability parameters."""
    buffer_strategy: Optional[Literal["aggressive", "balanced", "conservative"]] = Field(default=None)


class StreamingIntents(BaseModel):
    """Complete streaming intents extracted from user request."""
    movie_details: MovieDetails = Field(default_factory=MovieDetails)
    video_quality: VideoQuality = Field(default_factory=VideoQuality)
    network_requirements: NetworkRequirements = Field(default_factory=NetworkRequirements)
    audio_quality: AudioQuality = Field(default_factory=AudioQuality)
    reliability: Reliability = Field(default_factory=Reliability)

    def to_json(self, exclude_none: bool = False) -> str:
        """Convert to JSON string."""
        return self.model_dump_json(exclude_none=exclude_none, indent=2)

    def to_dict(self, exclude_none: bool = False) -> dict:
        """Convert to dictionary."""
        return self.model_dump(exclude_none=exclude_none)