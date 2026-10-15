from flask_wtf import FlaskForm
from wtforms import (
    StringField, PasswordField, SelectField, TextAreaField,
    BooleanField, SubmitField,
)
from wtforms.validators import DataRequired, Length, Optional, URL


class VaultEntryForm(FlaskForm):
    title = StringField(
        "Título",
        validators=[DataRequired(), Length(max=120)],
    )
    category = SelectField(
        "Categoría",
        choices=[
            ("server", "Servidor"),
            ("platform", "Plataforma"),
            ("api", "API / Token"),
            ("other", "Otro"),
        ],
        validators=[DataRequired()],
    )
    group_id = SelectField(
        "Grupo",
        validators=[Optional()],
        default="",
        # choices are now filtered by (owner, shared) for UX (ADR-005
        # Fase 4) and are no longer every group that exists — WTForms'
        # own choice-membership check must not become an accidental second
        # gate ahead of _validate_group_assignment(), which is the sole
        # authority and already rejects an out-of-scope/nonexistent id on
        # its own, with the real flash message and status code.
        validate_choice=False,
    )
    username = StringField(
        "Usuario",
        validators=[Optional(), Length(max=120)],
    )
    password = PasswordField(
        "Contraseña",
        validators=[Optional(), Length(max=500)],
    )
    url = StringField(
        "URL",
        validators=[Optional(), URL(), Length(max=250)],
    )
    expires_at = StringField(
        "Fecha de expiración",
        validators=[Optional()],
    )
    notes = TextAreaField(
        "Notas",
        validators=[Optional(), Length(max=2000)],
    )
    shared = BooleanField("Compartir con todos los analistas", default=True)
    submit = SubmitField("Guardar")
