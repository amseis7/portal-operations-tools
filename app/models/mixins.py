import json
from app.extensions import db


class VtInfoMixin:
    vt_last_check = db.Column(db.DateTime)
    vt_reputation = db.Column(db.Integer)
    vt_positives = db.Column(db.Integer, default=0)
    vt_total = db.Column(db.Integer, default=0)
    vt_permalink = db.Column(db.String(255))
    vt_md5 = db.Column(db.String(32))
    vt_sha1 = db.Column(db.String(40))
    vt_sha256 = db.Column(db.String(64))
    vt_motores_json = db.Column(db.Text)

    def set_motores(self, data: dict):
        self.vt_motores_json = json.dumps(data)

    def get_motores(self):
        return json.loads(self.vt_motores_json or "{}")