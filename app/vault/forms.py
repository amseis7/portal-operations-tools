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
