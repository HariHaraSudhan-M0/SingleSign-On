from flask import Blueprint,render_template,request,flash,redirect,url_for
from .models import User
from werkzeug.security import generate_password_hash,check_password_hash
from . import db
auth = Blueprint('auth', __name__)

@auth.route('/login',methods=['GET','POST'])
def login():
    return render_template("login.html",boolean=True)
@auth.route('/logout')
def logout():
    return "<p>Logout</p>"
@auth.route('/sign-up',methods=['GET','POST'])
def sign_up():
    if request.method=='POST':
        email=request.form.get('email')
        first_name=request.form.get('firstName')
        password1=request.form.get('password1')
        password2=request.form.get('password2')

        if len(email)<4:
            flash('email must be greater than 4 charaters',category='error')
        elif len(first_name)<2:
            flash('Firstname must be greater than 2 charaters',category='error')
        elif password1 != password2:
            flash('passwords dosent match',category='error')
        elif len(password1)<7:
            flash('password must be greater than 7 charaters',category='error')
        else:
            new_user=User(email=email,first_name=first_name,passsword=generate_password_hash(password1))
            db.session.add(new_user)
            db.session.commit()
            
            flash('account created',category='success')
            return redirect(url_for('views.home'))
            
    return render_template("signup.html")