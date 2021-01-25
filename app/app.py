# -*- coding: utf-8 -*-
import zipfile

from flask import Flask, render_template, request, flash, Markup, jsonify, redirect, url_for, send_from_directory

from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, SubmitField, BooleanField, PasswordField, IntegerField, TextField, \
    FormField, SelectField, FieldList
from wtforms.validators import DataRequired, Length
from wtforms.fields import *

from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_basicauth import BasicAuth

from forms import Dnp3, Modbus, S7, FinsTcp, FinsUdp, All
from libs.packer.protocol.tools import int_to_bytes
from libs.packer.maker.maker import pcap_maker
from libs.packer.maker.maker_dnp3 import make_dnp3_read_packets, make_dnp3_write_packets
from libs.packer.maker.maker_modbus import make_modbus_read_packets, make_modbus_write_packets
from libs.packer.maker.maker_omron import make_udp_fins_read_packets, make_udp_fins_write_packets
from libs.packer.maker.maker_fins_tcp import make_tcp_fins_read_packets, make_tcp_fins_write_packets
from libs.packer.maker.maker_s7 import make_s7_read_packets, make_s7_write_packets
from libs.packer.maker.json_maker_t import *
from setting import *
import os, time
from datetime import timedelta

from waitress import serve

app = Flask(__name__)
app.secret_key = 'dev'
app.config['BASIC_AUTH_USERNAME'] = 'admin'
app.config['BASIC_AUTH_PASSWORD'] = 'admin123456'
app.config['BASIC_AUTH_FORCE'] = True

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'

# set default button sytle and size, will be overwritten by macro parameters
app.config['BOOTSTRAP_BTN_STYLE'] = 'primary'
app.config['BOOTSTRAP_BTN_SIZE'] = 'sm'
# app.config['BOOTSTRAP_BOOTSWATCH_THEME'] = 'lumen'  # uncomment this line to test bootswatch theme
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = timedelta(seconds=5)

basic_auth = BasicAuth(app)

bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
csrf = CSRFProtect(app)


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/dnp3', methods=['GET', 'POST'])
def dnp3():
    form = Dnp3()
    if request.method == 'POST':
        type = request.form.get('type')
        address = request.form.get('address')
        start = request.form.get('start')
        amount = request.form.get('amount')
        bad_data = request.form.get('bad_data')
        bad_loc = request.form.get('bad_loc')
        sensitivity = request.form.get('sensitivity')
        file = ''
        if type == 'READ':
            pcap_maker(make_dnp3_read_packets, 'temp/dnp3_r.pcap', DMAC, SMAC, DIP, SIP, 20000, 42942,
                       int_to_bytes(address, 1), int(start), int(amount), int(bad_data), int(bad_loc), int(sensitivity))
            dnp3_r()
            file = 'dnp3_r.pcap'
        else:
            pcap_maker(make_dnp3_write_packets, 'temp/dnp3_w.pcap', DMAC, SMAC, DIP, SIP, 20000, 42942,
                       int_to_bytes(address, 1), start=int(start), amount=int(amount), bad_data=int(bad_data),
                       bad_loc=int(bad_loc), sensitivity=int(sensitivity))
            dnp3_w()
            file = 'dnp3_w.pcap'
        return redirect(url_for('making', file=file))

    return render_template('dnp3.html', form=form)


@app.route('/modbus', methods=['GET', 'POST'])
def modbus():
    form = Modbus()
    if request.method == 'POST':
        type = request.form.get('type')
        address = request.form.get('address')
        start = request.form.get('start')
        amount = request.form.get('amount')
        bad_data = request.form.get('bad_data')
        bad_loc = request.form.get('bad_loc')
        sensitivity = request.form.get('sensitivity')
        file = ''
        if type == 'READ':
            pcap_maker(make_modbus_read_packets, 'temp/modbus_r.pcap', DMAC, SMAC, DIP, SIP, 502, 9699,
                       int_to_bytes(address, 1), int(start), int(amount), int(bad_data), int(bad_loc), int(sensitivity))
            modbus_r()
            file = 'modbus_r.pcap'
        else:
            pcap_maker(make_modbus_write_packets, 'temp/modbus_w.pcap', DMAC, SMAC, DIP, SIP, 502, 9699,
                       int_to_bytes(address, 1), start=int(start), amount=int(amount), bad_data=int(bad_data),
                       bad_loc=int(bad_loc), sensitivity=int(sensitivity))
            modbus_w()
            file = 'modbus_w.pcap'
        return redirect(url_for('making', file=file))

    return render_template('modbus.html', form=form)


@app.route('/s7', methods=['GET', 'POST'])
def s7():
    form = S7()
    if request.method == 'POST':
        type = request.form.get('type')
        address = request.form.get('address')
        start = request.form.get('start')
        amount = request.form.get('amount')
        bad_data = request.form.get('bad_data')
        bad_loc = request.form.get('bad_loc')
        sensitivity = request.form.get('sensitivity')
        file = ''
        if type == 'READ':
            pcap_maker(make_s7_read_packets, 'temp/s7_r.pcap', DMAC, SMAC, DIP, SIP, 502, 9699,
                       int_to_bytes(address, 1), int(start), int(amount), int(bad_data), int(bad_loc), int(sensitivity))
            s7_r()
            file = 's7_r.pcap'
        else:
            pcap_maker(make_s7_write_packets, 'temp/s7_w.pcap', DMAC, SMAC, DIP, SIP, 502, 9699,
                       int_to_bytes(address, 1), start=int(start), amount=int(amount), bad_data=int(bad_data),
                       bad_loc=int(bad_loc), sensitivity=int(sensitivity))
            s7_w()
            file = 's7_w.pcap'
        return redirect(url_for('making', file=file))

    return render_template('s7.html', form=form)


@app.route('/fins_udp', methods=['GET', 'POST'])
def fins_udp():
    form = FinsUdp()
    if request.method == 'POST':
        type = request.form.get('type')
        address = request.form.get('address')
        start = request.form.get('start')
        amount = request.form.get('amount')
        bad_data = request.form.get('bad_data')
        bad_loc = request.form.get('bad_loc')
        sensitivity = request.form.get('sensitivity')
        file = ''
        if type == 'READ':
            pcap_maker(make_udp_fins_read_packets, 'temp/fins_udp_r.pcap', DMAC, SMAC, DIP, SIP, 502, 9699,
                       int_to_bytes(address, 1), int(start), int(amount), int(bad_data), int(bad_loc), int(sensitivity))
            fins_udp_r()
            file = 'fins_udp_r.pcap'
        else:
            pcap_maker(make_udp_fins_write_packets, 'temp/fins_udp_w.pcap', DMAC, SMAC, DIP, SIP, 502, 9699,
                       int_to_bytes(address, 1), start=int(start), amount=int(amount), bad_data=int(bad_data),
                       bad_loc=int(bad_loc), sensitivity=int(sensitivity))
            fins_udp_w()
            file = 'fins_udp_w.pcap'
        return redirect(url_for('making', file=file))

    return render_template('fins_udp.html', form=form)


@app.route('/fins_tcp', methods=['GET', 'POST'])
def fins_tcp():
    form = FinsTcp()
    if request.method == 'POST':
        type = request.form.get('type')
        address = request.form.get('address')
        start = request.form.get('start')
        amount = request.form.get('amount')
        bad_data = request.form.get('bad_data')
        bad_loc = request.form.get('bad_loc')
        sensitivity = request.form.get('sensitivity')
        file = ''
        if type == 'READ':
            pcap_maker(make_tcp_fins_read_packets, 'temp/fins_tcp_r.pcap', DMAC, SMAC, DIP, SIP, 502, 9699,
                       int_to_bytes(address, 1), int(start), int(amount), int(bad_data), int(bad_loc), int(sensitivity))
            fins_tcp_r()
            file = 'fins_tcp_r.pcap'
        else:
            pcap_maker(make_tcp_fins_write_packets, 'temp/fins_tcp_w.pcap', DMAC, SMAC, DIP, SIP, 502, 9699,
                       int_to_bytes(address, 1), start=int(start), amount=int(amount), bad_data=int(bad_data),
                       bad_loc=int(bad_loc), sensitivity=int(sensitivity))
            fins_tcp_w()
            file = 'fins_tcp_w.pcap'
        return redirect(url_for('making', file=file))

    return render_template('fins_tcp.html', form=form)


@app.route('/make_all', methods=['GET', 'POST'])
def make_all():
    form = All()
    if request.method == 'POST':
        type = request.form.get('type')
        address = request.form.get('address')
        start = request.form.get('start')
        amount = request.form.get('amount')
        bad_data = request.form.get('bad_data')
        bad_loc = request.form.get('bad_loc')
        sensitivity = request.form.get('sensitivity')
        file = ''
        if type == 'READ':
            pcap_maker(make_dnp3_read_packets, 'temp/dnp3_r.pcap', DMAC, SMAC, DIP, SIP, 20000, 42942,
                       int_to_bytes(address, 1), int(start), int(amount), int(bad_data), int(bad_loc), int(sensitivity))
            dnp3_r()
            pcap_maker(make_modbus_read_packets, 'temp/modbus_r.pcap', DMAC, SMAC, DIP, SIP, 502, 9699,
                       int_to_bytes(address, 1), int(start), int(amount), int(bad_data), int(bad_loc), int(sensitivity))
            modbus_r()
            pcap_maker(make_s7_read_packets, 'temp/s7_r.pcap', DMAC, SMAC, DIP, SIP, 502, 9699,
                       int_to_bytes(address, 1), int(start), int(amount), int(bad_data), int(bad_loc), int(sensitivity))
            s7_r()
            pcap_maker(make_udp_fins_read_packets, 'temp/fins_udp_r.pcap', DMAC, SMAC, DIP, SIP, 502, 9699,
                       int_to_bytes(address, 1), int(start), int(amount), int(bad_data), int(bad_loc), int(sensitivity))
            fins_udp_r()
            pcap_maker(make_tcp_fins_read_packets, 'temp/fins_tcp_r.pcap', DMAC, SMAC, DIP, SIP, 502, 9699,
                       int_to_bytes(address, 1), int(start), int(amount), int(bad_data), int(bad_loc), int(sensitivity))
            fins_tcp_r()
        else:
            pcap_maker(make_dnp3_write_packets, 'temp/dnp3_w.pcap', DMAC, SMAC, DIP, SIP, 20000, 42942,
                       int_to_bytes(address, 1), start=int(start), amount=int(amount), bad_data=int(bad_data),
                       bad_loc=int(bad_loc), sensitivity=int(sensitivity))
            dnp3_w()
            pcap_maker(make_modbus_write_packets, 'temp/modbus_w.pcap', DMAC, SMAC, DIP, SIP, 502, 9699,
                       int_to_bytes(address, 1), start=int(start), amount=int(amount), bad_data=int(bad_data),
                       bad_loc=int(bad_loc), sensitivity=int(sensitivity))
            modbus_w()
            pcap_maker(make_s7_write_packets, 'temp/s7_w.pcap', DMAC, SMAC, DIP, SIP, 502, 9699,
                       int_to_bytes(address, 1), start=int(start), amount=int(amount), bad_data=int(bad_data),
                       bad_loc=int(bad_loc), sensitivity=int(sensitivity))
            s7_w()
            pcap_maker(make_udp_fins_write_packets, 'temp/fins_udp_w.pcap', DMAC, SMAC, DIP, SIP, 502, 9699,
                       int_to_bytes(address, 1), start=int(start), amount=int(amount), bad_data=int(bad_data),
                       bad_loc=int(bad_loc), sensitivity=int(sensitivity))
            fins_udp_w()
            pcap_maker(make_tcp_fins_write_packets, 'temp/fins_tcp_w.pcap', DMAC, SMAC, DIP, SIP, 502, 9699,
                       int_to_bytes(address, 1), start=int(start), amount=int(amount), bad_data=int(bad_data),
                       bad_loc=int(bad_loc), sensitivity=int(sensitivity))
            fins_tcp_w()

        now = time.strftime("%Y-%m-%d-%H_%M_%S", time.localtime(time.time()))
        zfilename = 'all_' + now + '.zip'
        file_path = 'temp'
        fzip = zipfile.ZipFile('temp/' + zfilename, 'w', zipfile.ZIP_DEFLATED)
        for file in os.listdir(file_path):
            t_path = os.path.join(os.getcwd() + '\\temp', file)
            if os.path.isfile(t_path):
                if file.endswith('pcap') or file.endswith('json'):
                    fzip.write('temp/' + file)
        fzip.close()
        return redirect(url_for('making_all', file=zfilename))

    return render_template('make_all.html', form=form)


@app.route('/making/<string:file>')
def making(file):
    return render_template('making.html', file=file)


@app.route('/making_all/<string:file>')
def making_all(file):
    return render_template('making_all.html', file=file)


@app.route('/made/<string:file>')
def made(file):
    return render_template('made.html', file=file)


@app.route('/made_all/<string:file>')
def made_all(file):
    return render_template('made_all.html', file=file)


@app.route('/download/<string:file>')
def download(file):
    return send_from_directory(r"temp", filename=file, as_attachment=True)


@app.route('/tools')
def tools():
    return render_template("tools.html")


@app.route('/making_logfile/<string:file>')
def making_logfile(file):
    logfile = ''
    if file == 'dnp3_r.pcap':
        logfile = 'dnp3_r.json'
    if file == 'dnp3_w.pcap':
        logfile = 'dnp3_w.json'
    if file == 'modbus_r.pcap':
        logfile = 'modbus_r.json'
    if file == 'modbus_w.pcap':
        logfile = 'modbus_w.json'
    if file == 's7_r.pcap':
        logfile = 's7_r.json'
    if file == 's7_w.pcap':
        logfile = 's7_w.json'
    if file == 'fins_udp_w.pcap':
        logfile = 'fins_udp_w.json'
    if file == 'fins_udp_r.pcap':
        logfile = 'fins_udp_w.json'
    if file == 'fins_tcp_w.pcap':
        logfile = 'fins_tcp_w.json'
    if file == 'fins_tcp_r.pcap':
        logfile = 'fins_tcp_w.json'
    return render_template('making_logfile.html', file=logfile)


@app.route('/made_logfile/<string:file>')
def made_logfile(file):
    return render_template('made_logfile.html', file=file)


@app.route('/list_file')
def list_file():
    pcap_files = []
    json_files = []
    zip_files = []
    file_path = 'temp'
    for file in os.listdir(file_path):
        t_path = os.path.join(os.getcwd() + '\\temp', file)
        if os.path.isfile(t_path):
            if file.endswith('pcap'):
                pcap_files.append(file)
            if file.endswith('json'):
                json_files.append(file)
            if file.endswith('zip'):
                zip_files.append(file)
    return render_template('list_file.html', pcaps=pcap_files, jsons=json_files, zips=zip_files)


@app.route('/confirm_delete')
def confirm_delete():
    return render_template('confirm_delete.html')


@app.route(('/deleted'))
def deleted():
    file_path = 'temp'
    for file in os.listdir(file_path):
        t_path = os.path.join(os.getcwd() + '\\temp', file)
        if os.path.isfile(t_path):
            os.remove(t_path)
    return render_template('deleted.html')


if __name__ == '__main__':
    # serve(app, host='0.0.0.0', port=5000)
    app.debug = True
    app.run()
