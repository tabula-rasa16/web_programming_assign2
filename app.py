from flask import Flask, request, render_template, session
import json
import pymysql
# from typing import Optional

# from flask_pydantic import validate

from config import Config

from common.jsontools import *


# from cryptography.hazmat.primitives.asymmetric import rsa
# from cryptography.hazmat.primitives import serialization
# from cryptography.hazmat.primitives.asymmetric import padding
# from cryptography.hazmat.primitives import hashes
# import base64

import hashlib






app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = 'SUNZ0027'  # 设置session密钥


# 生成RSA密钥对
# PRIVATE_KEY = rsa.generate_private_key(
#     public_exponent=65537,
#     key_size=2048
# )
# PUBLIC_KEY = PRIVATE_KEY.public_key()

#生成salt
SALT = "SUNZ0027".encode('utf-8')



# Create a MySQL connector

db = pymysql.connect(host='localhost', port =13306, user='root', password='5903q1w2e3@Q', db='user_system', charset='utf8mb3') #本地
cursor = db.cursor()

cursor.execute("SELECT VERSION()")
 
# 使用 fetchone() 方法获取单条数据.
data = cursor.fetchone()
 
print ("Database version : %s " % data)


@app.route('/')
def index():
    username = session.get('username')
    if username:
        return render_template('home.html',r = username)
    else:
        return render_template('index.html',
                           title="My Flask App",
                           heading="Welcome to My Flask App",
                           content="This is a sample Jinja page.",
                           items=['Flask', 'Jinja2', 'Python'],
                           user="John Doe")


# 获取公钥
# @app.route('/getPublicKey')
# def get_public_key():
#     pem = PUBLIC_KEY.public_bytes(
#         encoding=serialization.Encoding.PEM,
#         format=serialization.PublicFormat.SubjectPublicKeyInfo
#     )
#     return jsonify({'public_key': pem.decode('utf-8')})

@app.route('/home')
def home():
    username = ""
    username = session.get('username')
    return render_template('home.html',r = username)



@app.route('/register', methods=['POST'])
def register():
    data = request.json
    # encrypted_password = data['encrypted_password']
    password = data['password']

    username = data['username']

    # 数据合法性判断

    if not username or not password:
        return response(code=400, message="Username or password cannot be empty!")
    

    # 注册逻辑
    # 判断用户是否已存在
    sql = "SELECT * FROM sys_user WHERE name = %s"
    cursor.execute(sql, (username,))
    result = cursor.fetchone()
    if result is not None:
        return response(code=400, message="User already exists!")
    else:
        # 用户不存在，则插入新用户
        # 解密密码
        # decrypted_password = PRIVATE_KEY.decrypt(
        #     base64.b64decode(encrypted_password),
        #     padding.PKCS1v15()
        # )

        # 加密密码,以便存储
        password = password.encode('utf-8') # 将密码encode为字节
        hashed_password =  hashlib.sha256(password+SALT).hexdigest()
        sql = "INSERT INTO sys_user (name, password) VALUES (%s, %s)"
        try:
            cursor.execute(sql, (username, hashed_password))
            db.commit()
        except pymysql.Error as e:
            db.rollback()
            return response(code=500, message=f"Database error: {e}")
    return response(code=200, message="Register success!")

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    # encrypted_password = data['encrypted_password']
    username = data['username']
    password = data['password']

    
    
    #记录不存在，继续以下逻辑
    # 判断用户是否存在
    sql = "SELECT * FROM sys_user WHERE name = %s"
    cursor.execute(sql, (username,))
    result = cursor.fetchone()
    if result is None:
        return response(code=400, message="User does not exist, Please register first!")
    else:
        # 用户存在，则验证密码
        storage_password = result[2]

        # 解密密码
        # decrypted_password = PRIVATE_KEY.decrypt(
        #     base64.b64decode(encrypted_password),
        #     padding.PKCS1v15()
        # )
        # 加密密码,并与数据库中密码比较
        password = password.encode('utf-8') # 将密码encode为字节
        hashed_password = hashlib.sha256(password+SALT).hexdigest()

        if hashed_password == storage_password:
            # 创建session
            session["username"] = username
            return response(code=200, message="Login successful!")
        else:
            return response(code=400, message="Invalid credentials!")
        

@app.route('/checkSession',methods=['GET'])
def checkSession():
    username = request.args.get('username')
    login_record = session.get(username)
    if login_record:
        return response(code=200, message="Login successful!")
    else:
        return response(code=400, message="Login status expired, please login again!")


@app.route('/logout',methods=['GET'])
def logout():
    session.pop('username', None)
    return response(code=200, message="Logout successful!")


if __name__ == '__main__':
    host = app.config.get('HOST', '127.0.0.1')  # 默认值为 '127.0.0.1'，如果未找到 'HOST' 配置项
    port = app.config.get('PORT', 5000)  # 默认值为 5000，如果未找到 'PORT' 配置项
    app.run(host=host, port=port)   