class InvalidPasswordError(Exception):
    """Exception raised for invalid passwords."""
    def __init__(self, message):
        super().__init__(message)