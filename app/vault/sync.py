import os
import stat
import threading
from uuid import UUID

from flask import current_app

from app.vault.crypto import decrypt


class VaultSyncService:
    """Exports all vault entries to a .kdbx file on a network path (SharePoint).
    The file is set read-only after writing so KeePass opens it in read-only mode.
    Sync runs in a background daemon thread to avoid blocking HTTP responses.
    """

    _lock = threading.Lock()

    def trigger_async(self, app):
        """Dispatch sync in a background thread. Safe to call after db.session.commit()."""
        path = app.config.get("VAULT_KDBX_PATH", "")
        password = app.config.get("VAULT_KDBX_PASSWORD", "")
        if not path or not password:
            return  # Sync not configured — skip silently
        t = threading.Thread(target=self._run, args=(app,), daemon=True)
        t.start()

    def _run(self, app):
        with app.app_context():
            with self._lock:
                self._export()

    def _export(self):
        from app.vault.models import VaultEntry, VaultGroup
        from pykeepass import create_database

        path = current_app.config["VAULT_KDBX_PATH"]
        password = current_app.config["VAULT_KDBX_PASSWORD"]

        try:
            # Lift read-only attribute so we can overwrite the file
            if os.path.exists(path):
                os.chmod(path, stat.S_IWRITE | stat.S_IREAD)

            kp = create_database(path, password=password)

            # Build KeePass group hierarchy
            kp_groups = {}
            groups = VaultGroup.query.order_by(VaultGroup.id).all()
            for g in groups:
                parent_kp = kp_groups.get(g.parent_id) or kp.root_group
                kp_groups[g.id] = kp.add_group(parent_kp, g.name, icon=g.icon_id)

            ungrouped = kp.add_group(kp.root_group, "Sin Grupo", icon=48)

            # Add entries
            for entry in VaultEntry.query.all():
                kp_group = kp_groups.get(entry.group_id) or ungrouped
                e = kp.add_entry(
                    kp_group,
                    title=entry.title,
                    username=entry.username,
                    password=decrypt(entry.password_enc),
                    url=entry.url or "",
                    notes=decrypt(entry.notes_enc) if entry.notes_enc else "",
                )
                try:
                    e.uuid = UUID(entry.uuid)
                except Exception:
                    pass  # Keep generated UUID if stored one is malformed

                if entry.expires_at:
                    e.expiry_time = entry.expires_at
                    e.expires = True

                for field in entry.custom_fields:
                    try:
                        e.set_custom_property(
                            field.field_key,
                            decrypt(field.field_value_enc),
                            protect=field.is_protected,
                        )
                    except Exception:
                        pass

            kp.save()
            # Re-apply read-only after writing
            os.chmod(path, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)

        except Exception as exc:
            current_app.logger.error("Vault kdbx sync failed: %s", exc)


vault_sync = VaultSyncService()
