from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, TextAreaField, BooleanField, SubmitField
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
    username = StringField(
        "Usuario",
        validators=[DataRequired(), Length(max=120)],
    )
    password = PasswordField(
        "Contraseña",
        validators=[Optional(), Length(max=500)],
    )
    url = StringField(
        "URL",
        validators=[Optional(), URL(), Length(max=250)],
    )
    notes = TextAreaField(
        "Notas",
        validators=[Optional(), Length(max=2000)],
    )
    shared = BooleanField("Compartir con todos los analistas", default=False)
    submit = SubmitField("Guardar")
