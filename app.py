from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from flask_wtf import FlaskForm
from wtforms import StringField, EmailField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
from werkzeug.security import generate_password_hash, check_password_hash
import os
import email_validator
from flask import Flask, request, render_template
from transformers import AutoModelForSequenceClassification, AutoTokenizer
import torch

from functools import wraps
from flask import redirect, url_for

app = Flask(__name__)
app.secret_key = os.urandom(24).hex()  # Use a random secret key

def init_db():
    with sqlite3.connect('users.db') as conn:
        print('con sucss')
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        conn.commit()

init_db()

class SignInForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')

class SignUpForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/signin", methods=['GET', 'POST'])
def signin():
    form = SignInForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        with sqlite3.connect('users.db') as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT password FROM users WHERE username = ?', (email,))
            user = cursor.fetchone()
            if user and check_password_hash(user[0], password):
                session['user'] = email
                flash('Successfully signed in!', 'success')
                return redirect(url_for('recomendation'))
            else:
                flash('Invalid credentials, please try again.', 'danger')

    return render_template("signin.html", form=form)

@app.route("/signup", methods=['GET', 'POST'])
def signup():
    form = SignUpForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data
        hashed_password = generate_password_hash(password)
        print(email)
        print(hashed_password)

        with sqlite3.connect('users.db') as conn:
            cursor = conn.cursor()
            try:
                cursor.execute('''
                    INSERT INTO users (name, username, password)
                    VALUES (?, ?, ?)
                ''', (name, email, hashed_password))
                conn.commit()
                flash('Account created successfully!', 'success')
                return redirect(url_for('signin'))
            except sqlite3.IntegrityError:
                flash('Username already exists!', 'danger')

    return render_template("signup.html", form=form)



def signin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('You need to sign in first!', 'warning')
            return redirect(url_for('signin'))
        return f(*args, **kwargs)
    return decorated_function

# Load the tokenizer and model correctly
tokenizer = AutoTokenizer.from_pretrained('ORF_best_model')
model = AutoModelForSequenceClassification.from_pretrained('ORF_best_model')
model.eval()  # Set the model to evaluation mode

# Class mapping
class_labels = {
    0: "Normal",
    1: "Fake Job"
}

@app.route("/prediction/", methods=['GET', 'POST'])
@signin_required
def recomendation():
    if request.method == 'POST':
        # Get the input text from the form
        text = request.form.get('text', '')

        # Preprocess the input with the tokenizer
        inputs = tokenizer(text, padding=True, truncation=True, return_tensors="pt")

        # Make prediction
        with torch.no_grad():
            outputs = model(**inputs)  # Pass the processed inputs to the model

        logits = outputs.logits

        # Get predicted class and probabilities
        probabilities = torch.softmax(logits, dim=1)
        predicted_class = torch.argmax(probabilities, dim=1).item()

        # Map predicted class to label
        predicted_label = class_labels.get(predicted_class, "Unknown")

        # Round the probability to 4 decimal places
        probability = round(probabilities[0][predicted_class].item(), 4)

        # Return the result in the template
        return render_template("prediction.html", predicted_label=predicted_label, text=text, probability=probability)

    # Render the form for GET request
    return render_template("prediction.html")

@app.route("/signout")
def signout():
    session.pop('user', None)
    flash('You have been signed out.', 'info')
    return redirect(url_for('home'))

if __name__ == "__main__":
    app.run(debug=True)
