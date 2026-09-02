"""OH MY FORTRESS — read-only multi-vendor configuration audit agent."""

__version__ = "1.0.1"
DISCLAIMER_VERSION = 3
DISCLAIMER_TEXT = (
    "OMF is a read-only configuration audit tool. It will authenticate to the target "
    "you specify and collect configuration evidence. It will not change the target. "
    "Suggested mitigations in the report are examples only. You, the auditor, are "
    "responsible for any change applied to the system. Review the session folder "
    "before sharing it; `raw/` contains unredacted vendor data. Proceed?"
)
