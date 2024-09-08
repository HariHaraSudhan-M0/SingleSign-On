from flask import Blueprint 

auth = Blueprint('auth', __name__)

@auth.route('/login',methods=['GET','POST'])
def login():
    return render_templates("login.html",boolean=True)
@auth.route('/logout')
def logout():
    return "<p>Logout</p>"
@auth.route('/sign-up',methods=['GET','POST'])
def sign_up():
    return render_templates("sign_up.html")