"""Module with system exceptions"""


class MemoryManagerError(Exception):

    """Base class for all exceptions thrown by the memory manager"""


class RegionCollectionError(MemoryManagerError):

    """Thrown if a memory region could not be collected, or if no region for collection was found"""
