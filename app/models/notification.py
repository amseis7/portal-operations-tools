from datetime import datetime
from app.extensions import db


class Notification(db.Model):
    __tablename__ = "notification"
    __table_args__ = (
        db.Index('ix_notification_read', 'is_read', 'timestamp'),
    )

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    message = db.Column(db.String(255))
    category = db.Column(db.String(50), index=True)
    is_read = db.Column(db.Boolean, default=False)
    link = db.Column(db.String(200))

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    user = db.relationship("User", backref="notifications")

    def __repr__(self):
        return f"<Notification {self.message}>"