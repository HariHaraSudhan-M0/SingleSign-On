from flask import Blueprint, render_template, flash, request, redirect, url_for
from flask_login import login_required, current_user
from .models import Book
from . import db

views = Blueprint('views', __name__)

@views.route('/', methods=['GET', 'POST'])
@login_required
def home():
    if request.method == 'POST':
        book_data = request.form.get('Book')
        if book_data is None or len(book_data) < 2:
            flash('Book name is too short', category='error')
        else:
            new_book = Book(book_name=book_data, user_id=current_user.id)  # Use correct field name
            db.session.add(new_book)
            db.session.commit()
            flash('Book added', category='success')
        return redirect(url_for('views.home'))  # Redirect to avoid form resubmission

    return render_template('home.html')  # Render the template with current_user context
