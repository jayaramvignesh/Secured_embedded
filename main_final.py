import argparse
import sqlite3
import requests
import smtplib
from email.mime.text import MIMEText
from OpenSSL import SSL
from flask import Flask, flash, redirect, render_template, request, session, abort, url_for, Markup
import hashlib
import os
from os import urandom
import time
import datetime
import random
from random import *
import MySQLdb
from bokeh.io import output_file
from bokeh.charts import show
from bokeh.plotting import figure
import numpy as np

app = Flask(__name__)

no_op = 0

global username_entered

global last_timestamp1
last_timestamp1 = 0

global last_timestamp
last_timestamp = 0

global failed_attempt
failed_attempt = 0

global failed_login_attempt
failed_login_attempt = 0

global sensor_id
sensor_id = 0

global sensor_keyvalue 
sensor_keyvalue = 0

conn = MySQLdb.connect('localhost','vjayaram','vjayaram','vjayaram' )
c = conn.cursor()

c.execute("create table if not exists user_credentials (email_id TEXT, password TEXT, username TEXT,salt TEXT, register TEXT)")
c.execute("create table if not exists admin_table (username TEXT, failed_login_attempts REAL,verified_email TEXT)")
c.execute("create table if not exists sensor_table (username TEXT, sensor_name TEXT, sensor_key TEXT,sensor_data TEXT, lower_limit TEXT, upper_limit TEXT)")
c.execute("create table if not exists login_ip_table (IP_address TEXT, login_attempt TEXT)")

query = " INSERT INTO user_credentials VALUES (%s,%s,%s,%s,%s)"

fromaddr = 'jayaramvignesh@gmail.com'
pwd = 'Saichaitra4$'
smtp_server = 'smtp.gmail.com:587'
t = ("-","-","-","-","-")

try:
    c.execute(query,t)
    conn.commit()
except:
    no_op = 0
    no_op

global otp_sent

def getHash(pwd):
    hashPass=hashlib.md5()
    hashPass.update(pwd)
    return(hashPass.hexdigest())

def validate(username,password):
    completion = False
    with conn:
        c.execute("SELECT username,password FROM user_credentials")
        conn.commit()
        rows= c.fetchall()
        for rows in rows:
            user = rows[0]
            epass = rows[1]
            if user == username and epass == password:
                completion = True
    return completion

@app.route('/')
def home():
    if session.get('logged_in'):
        response = redirect(url_for('user_choice'))
        return response
    else:
        return render_template('login.html')
    return render_template('login.html')

@app.route('/new_sensor',methods = ['GET', 'POST'])
def new_sensor():
    if session.get('logged_in'):
        if request.method == 'POST':
            username = request.form['username']   
            sensor_key = request.form['sensor_key']
            sensor_name = request.form['sensor_name'] 
            sensor_key_hashed = getHash(sensor_key)
            sensor_data = 0
            lower_limit = 0
            upper_limit = 100 
            with conn:
                c.execute("SELECT username,email_id FROM user_credentials WHERE username = %s",(username,))
                conn.commit()
                x = c.fetchall()            
            if(x):
                for x in x:
                    e_id = x[1]
            else:
                error = "No such username registered"
                return render_template("sensor_register.html" , error = error)
            with conn:
                c.execute("SELECT sensor_name FROM sensor_table WHERE username = %s",(username,))
                conn.commit()
                x = c.fetchall()            
            if(x):
                if(sensor_name == x[0][0]): 
                    error = "Sensor already registered"
                    return render_template("sensor_register.html" , error = error)
            
            sensor_query = "INSERT INTO sensor_table VALUES (%s,%s,%s,%s,%s,%s)"
            t = (username,sensor_name,sensor_key,sensor_data,lower_limit,upper_limit)
            with conn:
                c.execute(sensor_query,t)
                conn.commit()
                return render_template('user_choice.html')
        return render_template('sensor_register.html')
    else:
        error = "Please Login"
        return render_template('login.html' ,error = error)

@app.route('/user_choice', methods = ['GET','POST'])
def user_choice():
    global username_entered
    if session.get('logged_in'):    
        if request.method == 'POST':
            username = request.form['username']
            with conn:
                c.execute("SELECT username FROM sensor_table WHERE username = %s",(username,))
                conn.commit()
                x = c.fetchall()
                if(x):
                    u = x[0][0]
                    print u
                    if (u == username_entered):
                        with conn:
                            c.execute("SELECT username,sensor_name,sensor_data,upper_limit,lower_limit FROM sensor_table WHERE username = %s ",(username,))
                            conn.commit()     
                            rows = c.fetchall()
                            return render_template("sensor_view.html",rows=rows) 
                    else:
                        error = "You are not authenticated"
                        return render_template('user_choice.html',error = error)
                else:
                    error = "Username not registered. Please register first"
                    return render_template('user_choice.html',error=error)
        return render_template('user_choice.html')
    else:
        return home()

@app.route('/sid/<string:sid>', methods = ['GET', 'POST'])
def sid(sid):
    global sensor_id
    with conn:
        c.execute("SELECT sensor_key FROM sensor_table WHERE  sensor_key = %s",(sid,))
        conn.commit()
        x = c.fetchall()
        if(x):
            if(sid == x[0][0]):
                sensor_id = sid
                return user_choice() 
            else:
                error = "sensor key is invalid"
                return render_template('user_choice.html',error=error)

@app.route('/alert_receive/<string:alert>', methods = ['GET', 'POST'])
def alert_receive(alert):
    print "Ambient Light is"
    print alert
    return user_choice()


@app.route('/data_receive/<string:data>', methods = ['POST', 'GET'])
def data_receive(data):
    global sensor_id_
    sensor_data = data
    if request.method == 'POST':
        print data 
        with conn:
            c.execute("SELECT username,sensor_name,lower_limit,upper_limit FROM sensor_table WHERE sensor_key = %s",(sensor_id,))
            conn.commit()
            rows= c.fetchall()
            for rows in rows:
                uname = rows[0]
                sname = rows[1]
                l_limit = rows[2]
                u_limit = rows[3] 
            sensor_query = "INSERT INTO sensor_table VALUES (%s,%s,%s,%s,%s,%s)"
            t = (uname,sname,sensor_id,sensor_data,l_limit,u_limit)
            with conn:
                print "sensor insert"
                c.execute(sensor_query,t)
                conn.commit() 
	return user_choice() 
    else:
        no_op = 0
        no_op
	

@app.route('/data_graphical',methods = ['GET', 'POST'])
def data_graphical():
    global otp_sent
    global sensor_keyvalue
    if session.get('logged_in'):
        if request.method == 'POST':
            sensor_key = request.form['sensor_key']
            print sensor_key
            with conn:
                c.execute("SELECT sensor_key FROM sensor_table WHERE sensor_key = %s",(sensor_key,))
                conn.commit()
                x = c.fetchall()
                if (x):
                    print(x)
                    sensor_keyvalue = sensor_key
                    response = redirect('/data_graphic',code = 302)
                    return response
                else:
                    error = "invalid sensor key"
                    return render_template('data_graphical.html',error = error)
        return render_template('data_graphical.html')
    else:
        error = "Please login first"
        return render_template('login.html', error = error)

@app.route('/data_graphic',methods = ['GET','POST'])
def data_graphic():
    global sensor_keyvalue
    if session.get('logged_in'):
        with conn:
            data= []
            data_length = []
            c.execute("SELECT sensor_data FROM sensor_table WHERE sensor_key = %s",(sensor_keyvalue,))
            conn.commit()
            rows = c.fetchall()
            print rows
            for rows in rows:
                data.append(rows[0])
            print data
            a = len(data)
            print a
            for i in range (0,a):
                data_length.append(i+1)
            print data_length
            data_float = map(float, data)
            data_count = map(str , data_length)
            output_file('templates/data_graphic.html')
            p = figure(plot_width = 1000, plot_height = 1000 , x_range = data_count)
            p.line(data_count, data_float,color = 'navy', alpha = 0.5)
            p.xaxis.major_label_orientation = np.pi/6
            show(p)
            return render_template('data_graphic.html')
    else:
        error = "Please login first"
        return render_template(login.html,error =error)
                
@app.route('/delete',methods = ['GET','POST'])
def delete():
    if session.get('logged_in'):
        if request.method == 'POST':
            username = request.form['username']
            entered_pwd = request.form['password']
            print(username)
            with conn:
                c.execute("SELECT username,salt FROM user_credentials where username = %s",(username,))
                conn.commit()
                rows= c.fetchall()
                for rows in rows:
                    user = rows[0] 
                    salt = rows[1] 
                epass = getHash(entered_pwd+salt)
                completion = validate(username,epass)
                print(completion)
                if completion == False:
                    error = 'wrong username or password. try again'
                    return render_template('login.html',error=error)
                else:
                    print "hello"
                    with conn:
                        c.execute('''DELETE FROM user_credentials WHERE username = %s''',(username,))
                        conn.commit()
                    with conn:
                        c.execute('''DELETE FROM admin_table WHERE username = %s''',(username,))
                        conn.commit()
                    with conn:
                        c.execute('''DELETE FROM sensor_table WHERE username = %s''',(username,))
                        conn.commit()
                    response = redirect('/logout',code = 302)
                    return response
        return render_template('delete.html')    


@app.route('/sensor_limit',methods = ['GET','POST'])
def sensor_limit():
    global username_entered
    if session.get('logged_in'):
        if request.method == 'POST':
            username = request.form['username']
            sensor_name = request.form['sensor_name']
            sensor_key = request.form['sensor_key']
            upper_limit = request.form['upper_limit']
            lower_limit = request.form['lower_limit']      
            with conn:
                c.execute("SELECT username FROM user_credentials WHERE username = %s",(username,))
                conn.commit()     
                x = c.fetchall()
                if(x):
                    print x[0][0]
                    u = x[0][0]
                    if(x == username_entered):
                        no_op 
                        no__op = 0
                    else:
                        error = "You are not authenticated"
                        return render_template('sensor_limit.html' , error = error)
                else:
                    error = "Username not registered"
                    return render_template('sensor_limit.html',error = error)
            with conn:
                c.execute('''Select sensor_key FROM sensor_table WHERE sensor_name = %s''',(sensor_name,))
                conn.commit()
                x = c.fetchall()
                if(x):
                    if(sensor_key == x[0][0]):
                        with conn:
                            c.execute('''Select sensor_key FROM sensor_table WHERE sensor_name = %s''',(sensor_name,))
                            conn.commit()
                            y = c.fetchall()
                            if(y):
                                url = "https://192.168.1.150:5000/get_lowerlimit/"
                                url = url + str(lower_limit)
                                requests.post(url,verify = False)

                                url = "https://192.168.1.150:5000/get_upperlimit/"
                                url = url + str(upper_limit)
                                requests.post(url,verify = False)
                                
                                with conn:
                                    c.execute('''UPDATE sensor_table SET lower_limit = %s, upper_limit = %s WHERE sensor_key = %s''',(lower_limit,upper_limit,sensor_key))
                                    conn.commit()
                                response = redirect('/user_choice', code = 302)
                                return response 
                    else:
                        error = "Wrong Sensor Key"
                        return render_template('sensor_limit.html', error = error)
                else:
                    error = "sensor not registered"
                    return render_template('sensor_limit.html',error=error)
        return render_template('sensor_limit.html')
    else:
        error = "Please login first"
        return render_template('login.html',error = error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email_id = request.form['email_id']
        username = request.form['username'] 
        uname = (username)  
        password = request.form['password']
        password_conf = request.form['re_enter_password'] 
        with conn:
            c.execute("SELECT username FROM user_credentials WHERE username = %s",(username,))
            conn.commit()     
            x = c.fetchall()
            if(x):
                print(x[0])
                if (username == x[0][0]):
                    error = "Username Already Exists"
                    return render_template('register.html', error = error) 

        if(username != 'vija5019'):
            admin_query = "INSERT INTO admin_table VALUES (%s,%s,%s)"
            t = (username,0,'no')
            try:
                c.execute(admin_query,t)
                conn.commit()
            except:
                no_op = 0
                no_op
        if password == password_conf:
            salt = urandom(32).encode('base-64')
            epass = getHash(password+salt)
            query = " INSERT INTO user_credentials VALUES (%s,%s,%s,%s,%s)"
            t = (email_id,epass,username,salt,"False")
            try:
                c.execute(query,t)
                conn.commit()
            except:
                no_op = 0
                no_op
            session['logged_in'] = False
            sub = "Verify your email"
            body = "https://192.168.1.51:4000/verify/"+uname
            server = smtplib.SMTP(smtp_server)
            server.ehlo()
            server.starttls()        
            server.ehlo()
            msg = """From: %s \nTo: %s \nSubject: %s\n\n%s """ % (fromaddr, ",".join(email_id), sub, body)
            server.login(fromaddr,pwd)
            server.sendmail(fromaddr,email_id,msg)
            server.quit()
            flash('Thanks for registering')
            bodyText = Markup("<b>\n Verification Link has been sent to your email. Please verify your email\n</b>")
            return render_template('preverify.html',bodyText = bodyText)
        else:
            error = "password does not match"
            return render_template('register.html', error = error)
    return render_template('register.html')
   

@app.route('/verify/<string:uname>' ,methods = ['GET','POST'])
def verify(uname):
    session['logged_in'] = False
    try:    
        c.execute("SELECT username FROM user_credentials WHERE username = %s",(uname,))
        conn.commit() 
        x = c.fetchall()
        print(x)
    except:
        no_op = 0
        no_op
    
    if(uname == x[0][0]):         
        verified_value = "yes"
        print(verified_value)
        with conn:
            c.execute('''UPDATE admin_table SET verified_email = %s WHERE username = %s''',(verified_value,uname))
            conn.commit()
            print("hello") 

        register_value = "True"
        try:
            c.execute('''UPDATE user_credentials SET register = %s WHERE username = %s''',(register_value,uname))
            conn.commit()
            bodyText = Markup("<b>\n Congratulations Your Email has been verified\n</b>")
            return render_template('verify.html',bodyText = bodyText)
        except:
            no_op = 0
            no_op
    else:
        verified = "no"        
        admin_query = "UPDATE admin_table SET verified_email = %s WHERE username = %s"
        t = (verified, uname)
        try:
            c.execute(admin_query,t)
            conn.commit()
        except:
            no_op = 0
            no_op

        query = "UPDATE user_credentials SET register = %s WHERE username = %s"
        register_value = "False"
        t = (register_value,uname)
        try:
            c.execute(query,t)
            conn.commit()
            bodyText = Markup("<b>\n Sorry Try Again</b>")
            return render_template('verify.html',bodyText = bodyText)
        except:
            no_op = 0
            no_op

@app.route('/login', methods=['POST'])
def login():
    global username_entered
    global failed_attempt
    global failed_login_attempt
    global otp_sent
    global last_timestamp
    global last_timestamp1
    uname = request.form['username']
    entered_pwd = request.form['password']    
    body = str(randint(10000,1000000))
    sub = "OTP for web server login"
    otp_sent = body
    ip = request.remote_addr
    with conn:
        c.execute("SELECT login_attempt FROM login_ip_table WHERE IP_address = %s",(ip,))
        conn.commit()
        x = c.fetchall()
        if(x):
            no_op = 0
            no_op
        else:
            print(ip)
            with conn:
                query = "INSERT INTO login_ip_table VALUES (%s,%s)"
                count = 0
                t = (ip,count)
                c.execute(query,t)
                conn.commit()
    with conn:
        c.execute("SELECT username,email_id,salt,register FROM user_credentials where username = %s",(uname,))
        conn.commit()
        rows= c.fetchall()
        if(rows):
            for rows in rows:
                user = rows[0]
                e_id = rows[1]
                salt = rows[2]
                register = rows[3]
                epass = getHash(entered_pwd+salt)
                completion = validate(uname,epass)
        else:
            error = "username not registered"
            return render_template('login.html',error=error)
            
        if register == "True":
            if completion == False: 
                failed_login_attempt = failed_login_attempt + 1
                print failed_login_attempt
                query = "UPDATE login_ip_table SET login_attempt = %s WHERE IP_address = %s"
                t = (failed_login_attempt , ip)
                with conn:
                    c.execute(query,t)
                    conn.commit()
                if failed_login_attempt == 5:
                    current_timestamp = time.time()
                    if(current_timestamp - last_timestamp < 60):
                        print "hello hi how are you"
                        bodyText = Markup("<b>\n Login blocked. Wait for 5 mins</b>")
                        return render_template('sorry.html',bodyText = bodyText)
                    else:
                        failed_login_attempt = 0
                        query = "UPDATE login_ip_table SET login_attempt = %s WHERE IP_address = %s"
                        t = (failed_login_attempt , ip)
                        with conn:
                            c.execute(query,t)
                            conn.commit() 
                error = 'wrong username or password. try again'
                last_timestamp = time.time()
                failed_attempt = failed_attempt + 1 
                if failed_attempt == 5:
                    current_timestamp1 = time.time()
                    if(current_timestamp1 - last_timestamp1 < 60):
                        print "hello hi how are you"
                        bodyText = Markup("<b>\n Login blocked. Wait for 5 mins</b>")
                        return render_template('sorry.html',bodyText = bodyText)
                    else:
                        failed_attempt = 0
                        query = "UPDATE admin_table SET failed_login_attempts = %s WHERE username = %s"
                        t = (failed_attempt , uname)
                        with conn:
                            c.execute(query,t)
                            conn.commit()
                last_timestamp1 = time.time()
                admin_query = "UPDATE admin_table SET failed_login_attempts = %s WHERE username = %s"
                t = (failed_attempt, uname)
                with conn:
                    c.execute(admin_query,t)
                    conn.commit()
                return render_template('login.html',error=error)
            else:
                username_entered = uname
                if failed_login_attempt == 5:
                    current_timestamp = time.time()
                    if(current_timestamp - last_timestamp < 60):
                        print "hello hi how are you"
                        bodyText = Markup("<b>\n Login blocked. Wait for 5 mins</b>")
                        return render_template('sorry.html',bodyText = bodyText)
                    else:
                        failed_login_attempt = 0
                        query = "UPDATE login_ip_table SET login_attempt = %s WHERE IP_address = %s"
                        t = (failed_login_attempt , ip)
                        with conn:
                            c.execute(query,t)
                            conn.commit() 
                if failed_attempt == 5:
                    current_timestamp1 = time.time()
                    if(current_timestamp1 - last_timestamp1 < 60):
                        print "hello hi how are you"
                        bodyText = Markup("<b>\n Login blocked. Wait for 5 mins</b>")
                        return render_template('sorry.html',bodyText = bodyText)
                    else:
                        failed_attempt = 0
                        query = "UPDATE admin__table SET failed_login_attempts = %s WHERE username = %s"
                        t = (failed_attempt , uname)
                        with conn:
                            c.execute(query,t)
                            conn.commit()
                failed_login_attempt = 0
                failed_attempt = 0
                query = "UPDATE login_ip_table SET login_attempt = %s WHERE IP_address = %s"
                t = (failed_login_attempt , ip)
                with conn:
                    c.execute(query,t)
                    conn.commit()
                if(uname == "vija5019"):
                    session['logged_in'] = True
                    response = redirect(url_for('admin'))
                    return response
                toaddr = e_id
                server = smtplib.SMTP(smtp_server)
                server.ehlo()
                server.starttls()        
                server.ehlo()
                msg = """From: %s \nTo: %s \nSubject: %s\n\n%s """ % (fromaddr, ",".join(toaddr), sub, body)
                server.login(fromaddr,pwd)
                server.sendmail(fromaddr,toaddr,msg)
                server.quit()
                failed_attempt = 0
                admin_query = "UPDATE admin_table SET failed_login_attempts = %s WHERE username = %s"
                t = (failed_attempt, uname)
                with conn:
                    c.execute(admin_query,t)
                    conn.commit()
                response = redirect(url_for('OTP'))
                return response
        else:
            error = "Email has not been verified. Please verify the email"
            return render_template('login.html',error=error)

@app.route('/admin' , methods = ['GET','POST'])
def admin():
    if session.get('logged_in'):
        c.execute("SELECT * FROM admin_table")
        conn.commit()
        rows = c.fetchall()
        return render_template("admin.html",rows=rows)

@app.route('/OTP',methods = ['GET', 'POST'])
def OTP():
    global otp_sent
    if request.method == 'POST':
        otp = request.form['OTP'] 
        if otp == otp_sent:
            session['logged_in'] = True
            return home()
        else:
            error = 'Wrong OTP entered'
    return render_template('OTP.html')


@app.route('/logout')
def logout():
    session['logged_in'] = False
    session.clear()
    response = redirect('/',code = 302)
    return response
 
if __name__ == "__main__":
    app.secret_key = os.urandom(12)
    app.run(debug=False,host='192.168.1.51', port=4000, ssl_context = 'adhoc')
