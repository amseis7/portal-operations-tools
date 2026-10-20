from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length


class KnowledgeArticleForm(FlaskForm):
    title = StringField("Título", validators=[DataRequired(), Length(max=200)])
    problem_md = TextAreaField("Problema", validators=[DataRequired()])
    solution_md = TextAreaField("Solución / Procedimiento", validators=[DataRequired()])
    platform = StringField("Marca", validators=[Length(max=120)])
    tags_raw = StringField("Tags (separados por coma)", validators=[Length(max=300)])
    submit = SubmitField("Guardar")
