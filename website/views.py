from flask import Blueprint, render_template, flash, request
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
            flash('book name is too short', category='error')
        else:
            new_book = Book(data=book_data, user_id=current_user.id) 
            db.session.add(new_book)
            db.session.commit()
            flash('book added', category='success')
    return ''
