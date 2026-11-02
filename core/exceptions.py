class ShaheenError(Exception):
    """Base exception for Shaheen."""


class ConfigurationError(ShaheenError):
    pass


class DatabaseError(ShaheenError):
    pass


class CaptureError(ShaheenError):
    pass


class PacketAnalysisError(ShaheenError):
    pass


class AIServiceError(ShaheenError):
    pass
