from flask import Flask, request, redirect, url_for, render_template, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from werkzeug.security import check_password_hash, generate_password_hash

app=Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///DB.sqlite3'
app.config['SECRET_KEY']='VELE2128506'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False

db=SQLAlchemy(app)
login_manager=LoginManager(app)

tags=db.Table(
    'tags',
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id')),
    db.Column('post_id', db.Integer, db.ForeignKey('post.id')),
)

class Post(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    text=db.Column(db.String(1025), nullable=False)

    def __init__(self, text, tags_string):
        self.text=text
        self.tags=[]
        for tag_name in tags_string.split():
            tag=Tag.query.filter(Tag.text==tag_name).first()
            if not tag:
                tag=Tag(text=tag_name)
            self.tags.append(tag)

class Tag(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    text=db.Column(db.String(60), nullable=False)
    posts=db.relationship(Post, secondary=tags, lazy='subquery', backref='tags')

    def __str__(self):
        return '#'+self.text

class User(db.Model, UserMixin):
    id=db.Column(db.Integer, primary_key=True)
    login=db.Column(db.String(32), nullable=False, unique=True)
    name=db.Column(db.String(70))
    password=db.Column(db.String(60), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

db.create_all()

@app.route('/')
def start():
    return redirect(url_for('login'))

@app.route('/login', methods=["GET", "POST"])
def login():
    login=request.form.get('login')
    password=request.form.get("password")
    user=User.query.filter_by(login=login).first()
    if user and password:
        if check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('main'))
        else:
            flash('login or password is not correct')
    else:
        flash('please fill all fields')

    return render_template('login.html')

@app.route('/register', methods=["GET", "POST"])
def register():
    login = request.form.get('login')
    name = request.form.get('name')
    password = request.form.get("password")
    password2 = request.form.get("password2")
    user = User.query.filter_by(login=login).first()
    if not(login or name or password or password2):
        flash('please fill all fields')
    elif password != password2:
        flash('password should be equal')
    else:
        hash_password=generate_password_hash(password)
        new_user=User(login=login, name=name, password=hash_password)
        db.session.add(new_user)
        db.session.commit()
        flash(f'User {login} added successfully')

    return render_template('register.html')

@app.route('/logout', methods=["GET", "POST"])
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/main')
@login_required
def main():
    return render_template('index.html', posts=Post.query.all())

@app.route('/tag/<int:pk>')
@login_required
def tag(pk):
    return render_template('tag.html', tag=Tag.query.get(pk))


@app.route('/add_post', methods=["POST"])
def add_post():
    text=request.form.get('text')
    tags_string=request.form.get('tags')
    if text and tags_string:
        post=Post(text=text, tags_string=tags_string)
        db.session.add(post)
        db.session.commit()
    return redirect(url_for('main'))

if __name__=='__main__':
    app.run(port=5003, debug=True)