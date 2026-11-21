class ConfigLedgerError(Exception):
    """Base error for configuration-ledger operations."""


class ConfigStoreNotConfiguredError(ConfigLedgerError):
    pass


class ConfigStoreFolderMissingError(ConfigLedgerError):
    pass


class ConfigSnapshotError(ConfigLedgerError):
    pass


class ConfigSnapshotIntegrityError(ConfigSnapshotError):
    pass


class ConfigHistoryError(ConfigLedgerError):
    pass


class ConfigHistoryConflictError(ConfigHistoryError):
    pass


class ConfigVersionNotFoundError(ConfigHistoryError):
    pass


class SensitiveConfigError(ConfigLedgerError):
    pass
