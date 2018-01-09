try:
    from collections import OrderedDict
except ImportError:
    try:
        from ordereddict import OrderedDict
    except ImportError:
        import warnings
        warnings.warn("git-python needs the ordereddict module installed in python below 2.6 and below.")
        warnings.warn("Using standard dictionary as substitute, and cause reordering when writing git config")
        OrderedDict = dict
