import os
import secrets
import functools
from werkzeug.security import check_password_hash, generate_password_hash

from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func


# settings


basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

app.config['SQLALCHEMY_DATABASE_URI'] =\
        'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'banana'

db = SQLAlchemy(app)


# models


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(80), nullable=False)
    password = db.Column(db.Text, nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    token = db.Column(db.Text, nullable=True)

    def as_dict(self):
       return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey(User.id))
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    updated_at = db.Column(db.DateTime(timezone=True))
    text = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(80), nullable=False, server_default='NEW')

    def as_dict(self):
       return {c.name: getattr(self, c.name) for c in self.__table__.columns}


# endpoints


def login_required(func):
    @functools.wraps(func)
    def wrap(*args, **kwargs):
        token = request.json.get("auth_token", None)
        if token:
            user = db.session.query(User).filter(User.token == token).first()
            if user:
                return func(*args, **kwargs)
        return jsonify(
            status='ERR',
            code='401',
            message='Access denied',
            data=None
        )
    return wrap


@app.route('/api/tasks', methods=["POST"])
def get_tasks():
    ok = True
    error_msg = None
    result = []
    pages_count = 1

    fields = [
        Task.id,
        Task.text,
        Task.updated_at,
        Task.status,
        User.username,
        User.email
    ]

    sorting = request.json['sorting']
    ordering_field = User.username
    if sorting['field'] == 'email':
        ordering_field = User.email
    elif sorting['field'] == 'status':
        ordering_field = Task.status

    pagination = request.json['pagination']
    paginationKwargs = {"page": pagination['curPage'], "per_page": pagination['itemsPerPage']}

    try:
        if sorting['type'] == 'ASC':
            tasks_paginator = db.session.query(*fields).join(User) \
                                .order_by(func.lower(ordering_field)) \
                                .paginate(**paginationKwargs)
        else:
            tasks_paginator = db.session.query(*fields).join(User) \
                                .order_by(func.lower(ordering_field).desc()) \
                                .paginate(**paginationKwargs)
        for t in tasks_paginator.items:
            result.append({
                "id": t.id,
                "username": t.username,
                "email": t.email,
                "text": t.text,
                "status": t.status,
                "updated_at": t.updated_at,
            })
        pages_count = tasks_paginator.pages
    except Exception as e:
        ok = False
        error_msg = f"Server error : {e}"

    if not ok:
        return jsonify(
            status='ERR',
            message=error_msg,
            data=None,
            totalPages=None
        )
    return jsonify(
        status='OK',
        message='Tasks recieved successfully',
        data=result,
        totalPages=pages_count
    )


@app.route('/api/create', methods=["POST"])
def create_task():
    ok = True
    error_msg = None
    result = None

    username = request.json['username']
    email = request.json['email']
    user = db.session.query(User).filter(User.username == username, User.email == email).first()
    if user is None:
        try:
            user = User(username=username, email=email)
            db.session.add(user)
            db.session.commit()
        except Exception as e:
            ok = False
            error_msg = f"Server error : {e}"

    try:
        task = Task(user_id=user.id, text=request.json["text"])
        db.session.add(task)
        db.session.commit()
    except Exception as e:
        ok = False
        error_msg = f"Server error : {e}"

    if not ok:
        return jsonify(
            status='ERR',
            message=error_msg
        )
    return jsonify(
        status='OK',
        message='Task saved successfully',
    )


@app.route('/api/update', methods=["POST"])
@login_required
def update_task():
    ok = True
    error_msg = None
    result = None

    try:
        task_id = request.json['id']
        task = db.session.query(Task).filter(Task.id == task_id).first()

        task.text = request.json["text"]
        task.status = request.json["status"]
        task.updated_at = func.now()
        db.session.commit()
    except Exception as e:
        ok = False
        error_msg = f"Server error : {e}"

    if not ok:
        return jsonify(
            status='ERR',
            message=error_msg
        )
    return jsonify(
        status='OK',
        message='Task saved successfully'
    )


@app.route('/api/done', methods=["POST"])
@login_required
def mark_task_as_done():
    ok = True
    error_msg = None
    result = None

    try:
        task = db.session.query(Task).filter(Task.id == request.json['task_id']).first()
        task.status = 'DONE'
        db.session.commit()
    except Exception as e:
        ok = False
        error_msg = f"Server error : {e}"

    if not ok:
        return jsonify(
            status='ERR',
            message=error_msg
        )
    return jsonify(
        status='OK',
        message='Task marked as done successfully'
    )


@app.route('/api/auth', methods=["POST"])
def get_credentails():
    token = request.json.get('auth_token', None)
    if token:
        user = db.session.query(User).filter(User.token == token).first()
        if user:
            return jsonify(
                userData={
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "is_admin": user.is_admin,
                }
            )
    return jsonify(userData=None)


@app.route('/api/register', methods=["POST"])
def register():
    ok = True
    error_msg = None

    username = request.json['username']
    password = request.json['password']
    email = request.json['email']

    try:
        token = secrets.token_hex()
        user = User(
            username=username, 
            password=generate_password_hash(password), 
            email=email,
            token=token
        )
        db.session.add(user)
        db.session.commit()
    except Exception as e:
        ok = False
        error_msg = f"Server error : {e}"

    if not ok:
        return jsonify(
            status='ERR',
            message=error_msg,
            data=None
        )

    return jsonify(
        status='OK',
        message='You registered successfully',
        data={
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "is_admin": user.is_admin,
            "token": user.token
        }
    )


@app.route('/api/login', methods=["POST"])
def login():
    ok = True
    error_msg = None

    username = request.json['username']
    password = request.json['password']

    user = db.session.query(User).filter(User.username == username, User.password != None).first()

    if user is None:
        ok = False
        error_msg = 'Incorrect username'
    elif not check_password_hash(user.password, password):
        ok = False
        error_msg = 'Incorrect password'
    else:
        try:
            token = secrets.token_hex()
            user.token = token
            db.session.commit()
        except Exception as e:
            ok = False
            error_msg = f"Server error : {e}"

    if not ok:
        return jsonify(
            status='ERR',
            message=error_msg,
            data=None
        )

    return jsonify(
        status='OK',
        message='You logged in successfully',
        data={
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "is_admin": user.is_admin,
            "token": user.token
        }
    )


@app.route('/api/logout', methods=["POST"])
def logout():
    return jsonify(
        status='OK',
        message='You logged out successfully'
    )
