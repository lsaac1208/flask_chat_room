from flask import Flask, render_template, request, redirect, url_for, flash
from flask_socketio import SocketIO, emit
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import pytz

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
db = SQLAlchemy(app)
socketio = SocketIO(app)
login_manager = LoginManager(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('用户名', validators=[DataRequired()])
    password = PasswordField('密码', validators=[DataRequired()])
    submit = SubmitField('登录')

class RegistrationForm(FlaskForm):
    username = StringField('用户名', validators=[DataRequired()])
    password = PasswordField('密码', validators=[DataRequired(), EqualTo('confirm_password', message='密码必须相同')])
    confirm_password = PasswordField('确认密码', validators=[DataRequired()])
    submit = SubmitField('注册')

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50))
    message = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            login_user(user)
            flash(f'欢迎回来，{username}！', 'info')
            return redirect(url_for('chatroom'))
        else:
            flash('用户名或密码错误', 'error')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('用户名已存在', 'error')
        else:
            new_user = User(username=username, password=password)
            db.session.add(new_user)
            db.session.commit()
            flash('注册成功，请登录。', 'success')
            return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/chatroom')
@login_required
def chatroom():
    messages = Message.query.order_by(Message.timestamp.desc()).limit(50).all()
    messages.reverse()
    formatted_messages = []
    for message in messages:
        tz = pytz.timezone('Asia/Shanghai')
        formatted_time = message.timestamp.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S")
        formatted_message = f"[{formatted_time}] {message.username}: {message.message}"
        formatted_messages.append(formatted_message)
    return render_template('chatroom.html', username=current_user.username, messages=formatted_messages)

@socketio.on('connect')
def handle_connect():
    welcome_message = f'{current_user.username} 进入了聊天室'
    emit('message', str(welcome_message), broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    leave_message = f'{current_user.username} 离开了聊天室'
    emit('message', str(leave_message), broadcast=True)

@socketio.on('message')
@login_required
def handle_message(data):
    message = data['message']
    anonymous = data['anonymous']
    if anonymous:
        username = '匿名用户'
    else:
        username = current_user.username
    current_time = datetime.now(pytz.timezone('Asia/Shanghai'))
    formatted_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
    formatted_message = f"[{formatted_time}] {username}: {message}"
    new_message = Message(username=username, message=message, timestamp=current_time)  # 将格式化后的时间戳存入数据库
    db.session.add(new_message)
    db.session.commit()
    emit('message', formatted_message, broadcast=True)

@socketio.on('private_message')
@login_required
def handle_private_message(data):
    recipient = data['username']
    message = data['message']
    emit('message', {'username': current_user.username, 'message': '发送给 ' + recipient + ' 的私信：' + message}, room=recipient)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('再见，您已退出登录。', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        socketio.run(app)
