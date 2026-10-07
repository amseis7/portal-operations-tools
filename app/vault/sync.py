import os
import stat
import threading
from datetime import datetime
from uuid import UUID

from flask import current_app

from app.vault.crypto import decrypt


class VaultSyncService:
    """Exports all vault entries to a .kdbx file on a network path.
    The file is set read-only after writing so KeePass opens it in read-only mode.
    Sync runs in a background daemon thread to avoid blocking HTTP responses.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self.last_sync_at = None      # datetime UTC of last attempt
        self.last_sync_ok = None      # True=success, False=error, None=never
        self.last_sync_entries = 0    # number of entries written

    def trigger_async(self, app):
        """Dispatch sync in a background thread. Safe to call after db.session.commit()."""
        from app.vault.models import VaultSyncConfig
        cfg = VaultSyncConfig.query.first()
        path = (cfg.kdbx_path if cfg else '') or app.config.get("VAULT_KDBX_PATH", "")
        has_auth = bool(
            (cfg and cfg.kdbx_password_enc) or
            (cfg and cfg.kdbx_keyfile_path) or
            app.config.get("VAULT_KDBX_PASSWORD", "")
        )
        if not path or not has_auth:
            return
        t = threading.Thread(target=self._run, args=(app,), daemon=True)
        t.start()

    def _run(self, app):
        with app.app_context():
            with self._lock:
                self._export()

    def _export(self):
        from app.vault.models import VaultEntry, VaultGroup, VaultSyncConfig
        from pykeepass import create_database

        cfg = VaultSyncConfig.query.first()
        path = (cfg.kdbx_path if cfg else '') or current_app.config.get("VAULT_KDBX_PATH", "")
        password = None
        keyfile = None

        if cfg:
            if cfg.kdbx_password_enc:
                password = decrypt(cfg.kdbx_password_enc)
            keyfile = cfg.kdbx_keyfile_path or None

        if not password:
            password = current_app.config.get("VAULT_KDBX_PASSWORD", "") or None

        entry_count = 0

        try:
            # Lift read-only attribute so we can overwrite the file
            if os.path.exists(path):
                os.chmod(path, stat.S_IWRITE | stat.S_IREAD)

            kp = create_database(path, password=password, keyfile=keyfile)

            # Build KeePass group hierarchy
            kp_groups = {}
            groups = VaultGroup.query.order_by(VaultGroup.id).all()
            for g in groups:
                parent_kp = kp_groups.get(g.parent_id) or kp.root_group
                kp_groups[g.id] = kp.add_group(parent_kp, g.name)

            ungrouped = kp.add_group(kp.root_group, "Sin Grupo")

            # Add entries
            for entry in VaultEntry.query.all():
                try:
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
                    except Exception as exc:
                        current_app.logger.warning("Vault sync: malformed uuid %r on entry %d: %s", entry.uuid, entry.id, exc)

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
                        except Exception as exc:
                            current_app.logger.warning("Vault sync: skipping field %r on entry %d: %s", field.field_key, entry.id, exc)

                    entry_count += 1
                except Exception as exc:
                    current_app.logger.warning("Vault sync: skipping entry %d (%r): %s", entry.id, entry.title, exc)

            kp.save()
            self.last_sync_ok = True
            self.last_sync_entries = entry_count
            current_app.logger.info("Vault kdbx sync OK — %d entradas → %s", entry_count, path)
        except Exception as exc:
            current_app.logger.error("Vault kdbx sync failed: %s", exc)
            self.last_sync_ok = False
        finally:
            self.last_sync_at = datetime.utcnow()
            if os.path.exists(path):
                os.chmod(path, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)


vault_sync = VaultSyncService()
