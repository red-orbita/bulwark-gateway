"""Binary artifact scanners (stdlib-only, never deserialize).

Home of the model-artifact opcode scanner, relocated here from ``admin/`` so it
can be shared by BOTH consumers without violating layer isolation:
  * the admin SkillSpector pipeline (``admin.services.skill_scanner``), and
  * the proxy's output-path ``ArtifactOutputScanner`` (``src.scanners.output``).

The dependency direction is ``admin -> src`` (allowed); ``src`` never imports
``admin``. The engine itself is pure stdlib (``pickletools``) and never
deserializes untrusted bytes.
"""

from src.scanners.artifacts import model_artifact_scanner

__all__ = ["model_artifact_scanner"]
