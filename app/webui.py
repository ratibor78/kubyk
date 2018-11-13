import os
from app import db
from app import app
from flask_wtf import FlaskForm
from wtforms.validators import (
    InputRequired, Length, DataRequired, Optional, IPAddress, Regexp
)
from wtforms import (
    StringField, PasswordField, BooleanField, SelectField, TextAreaField,
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask import (
    json, render_template, make_response,
    redirect, url_for, request, Response
)
from flask_login import (
    LoginManager, UserMixin, login_user,
    login_required, logout_user, current_user
)


pwd = os.path.abspath(os.path.dirname(os.path.realpath(__file__)))


# Func for validating are the input = ipV4
def validIP(address):
    parts = address.split(".")
    if len(parts) != 4:
        return False
    try:
        for item in parts:
            if not 0 <= int(item) <= 256:
                return False
        return True
    except (AssertionError, ValueError):
        return False


app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# Slack config
slack_name = app.config['SLACK_NAME']
slack_channel = app.config['SLACK_CHANNEL']
webhook_url = app.config['WEBHOOK_URL']
send_to_slack = app.config['SEND_TO_SLACK']
delivery_log = app.config['DELIVERY_LOGS']


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    password = db.Column(db.String(80))

    def set_password(self, password):
        self.password = generate_password_hash(password, method='sha256')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=2, max=35)]) # NOQA
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)]) # NOQA
    remember = BooleanField('remember me')


class RegisterForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=35)]) # NOQA
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)]) # NOQA


class ChangepassForm(FlaskForm):
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)]) # NOQA


class Checkip(FlaskForm):
    checkurl = StringField('checkurl', validators=[Length(min=0, max=80)]) # NOQA
    userpass = StringField('userpass', validators=[Length(min=0, max=80)]) # NOQA


class FindipForm(FlaskForm):
    findip = StringField('findip', validators=[InputRequired(), Length(min=7, max=80)]) # NOQA
    rtonly = BooleanField('Search IP\'s only in Core0/1 route tables') # NOQA


class IpdeliverForm(FlaskForm):
    vlanid = StringField('vlanid', validators=[Optional(), Length(min=1, max=10), Regexp('^[0-9]', message='Vlan must contain only digits')]) # NOQA
    ipdest = StringField('ipdest', validators=[Optional(), IPAddress(ipv4=True)]) # NOQA
    sshport = StringField('sshport', validators=[Optional(), Length(min=1), Regexp('^[0-9]')], default='22') # NOQA
    status = SelectField('Add/Remove IP\'s', validators=[DataRequired()], choices=[("", ""), ("Add", "Add IP's"), ("Remove", "Remove IP's")]) # NOQA
    ipdbname = SelectField('Select IPDB Customer', validators=[DataRequired()], choices=[("", "")]) # NOQA
    ipslist = TextAreaField('Input IP\'s separated by "space"', validators=[InputRequired(), Length(min=7), Regexp('^[0-9]')]) # NOQA
    iplista = BooleanField('Add IP\'s to <b>ip_lista</b> & <b>ip_lista.cc</b> (Only if file exist)') # NOQA
    delipserv = BooleanField('Delete IP\'s from destination server also') # NOQA
    delipiplist = BooleanField('Delete IP\'s from <b>ip_lista</b> & <b>ip_lista.cc</b> (Only if file exist)') # NOQA


class SelectipForm(FlaskForm):
    status = SelectField('Quick or Extended', validators=[DataRequired()], choices=[("Quick", "Quick mode"), ("Extended", "Extended mode")]) # NOQA
    countips = StringField('Count IP\'s', validators=[Optional(), Length(min=1, max=10), Regexp('^\d+$', message='IP\'s count must contain only digits')]) # NOQA
    ipdbname = SelectField('IPDB Customer', validators=[DataRequired()], choices=[("", "")]) # NOQA
    geo = SelectField('Select GEO ', validators=[DataRequired()], choices=[("", "")]) # NOQA
    geomaxpercnet = StringField('IP per cnet', validators=[Optional(), Length(min=1, max=10), Regexp('^\d+$', message='Must contain only digits')], default='1')  # NOQA
    noresilans = BooleanField('no-resilans')
    provider = SelectField('Specific provider', validators=[DataRequired()], choices=[("5", "5"), ("6", "6"), ("4", "4"), ("1", "1"), ("All", "All")]) # NOQA


class getipForm(FlaskForm):
    status = SelectField('Quick or Extended', validators=[DataRequired()], choices=[("Quick", "Quick mode"), ("Extended", "Extended mode")]) # NOQA
    iptype = SelectField('Type of Ip\'s', validators=[DataRequired()], choices=[("all", "All"), ("proxy", "Proxy"), ("cgn", "Cgn")]) # NOQA
    countips = StringField('Count IP\'s', validators=[Optional(), Length(min=1, max=10), Regexp('^\d+$', message='IP\'s count must contain only digits')]) # NOQA
    ipdbname = SelectField('IPDB Customer', validators=[DataRequired()], choices=[("", "")]) # NOQA
    cc = StringField('Geo IP', validators=[Optional(), Length(min=2, max=2)]) # NOQA
    geomaxpercnet = StringField('IP per cnet', validators=[Optional(), Length(min=1, max=10), Regexp('^\d+$', message='Must contain only digits')], default='1')  # NOQA
    noresilans = BooleanField('no-resilans')
    provider = SelectField('Specific provider', validators=[DataRequired()], choices=[("5", "5"), ("6", "6"), ("4", "4"), ("1", "1"), ("All", "All")]) # NOQA


class SelectIpdeliverForm(FlaskForm):
    vlanid = StringField('vlanid', validators=[Optional(), Length(min=1, max=10), Regexp('^[0-9]', message='Vlan must contain only digits')]) # NOQA
    ipdest = StringField('ipdest', validators=[Optional(), IPAddress(ipv4=True)]) # NOQA
    sshport = StringField('sshport', validators=[Optional(), Length(min=1), Regexp('^[0-9]')], default='22') # NOQA
    ipdbname = SelectField('Select IPDB Customer', validators=[DataRequired()], choices=[("", "")]) # NOQA
    iplista = BooleanField('Add IP\'s to <b>ip_lista</b> & <b>ip_lista.cc</b> (Only if file exist)') # NOQA


@app.route('/users')
@login_required
def users():
    users = User.query.all()
    return render_template('users.html', users=users, user=current_user.username) # NOQA


@app.route('/userdel/<user>', methods=['GET', 'POST'])
@login_required
def userdel(user):
    form = LoginForm()
    if request.method == 'POST':
        User.query.filter_by(username=user).delete()
        db.session.commit()
        return redirect(url_for('users'))
    return render_template('delete.html', user=user, form=form) # NOQA


@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ''
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('index'))
        error = 'Invalid Username or Password !'
        return render_template('login.html', form=form, error=error) # NOQA
    else:
        if request.method == 'POST':
            error = 'Empty or not valid input'
        return render_template('login.html', form=form, error=error)
    return render_template('login.html', form=form, error=error)


@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    error = ''
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256') # NOQA
        new_user = User(username=form.username.data, password=hashed_password) # NOQA
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('users'))
    else:
        if request.method == 'POST':
            error = 'Empty or not valid input'
        return render_template('create.html', form=form, error=error)
    return render_template('create.html', form=form)


@app.route('/test/<customer>', methods=['GET', 'POST'])
@login_required
def test(customer):
    def generate():
        total_proxies = len(mysql.get_proxy_ips(customer))
        processed = 0
        dead_ips_list = []
        for status in checkip.curl_multi_test(cname=customer):
            processed += 1
            if status.startswith('Failed'):
                dead_ips_list.append(status.split(' ')[1])
            yield json.dumps(
                {
                    "status": "in_progress",
                    "message": "%s IPs checked from total %s" % (
                        processed, total_proxies
                    )
                }
            ) + '\n'
        yield json.dumps(
            {
                "status": "done",
                "message": "%s IP's are good and %s IP's are dead" % (total_proxies - len(dead_ips_list), len(dead_ips_list)), # NOQA
                "dead_ips": dead_ips_list
            }
        ) + '\n'
    return Response(generate(), mimetype='text/event-stream')


@app.route('/checkips/<customer>', methods=['GET', 'POST'])
@login_required
def checkips(customer):
    form = Checkip()
    if form.validate_on_submit():
        result = ipcheck.check_ips(cname=customer, cpass=form.userpass.data, website=form.checkurl.data) # NOQA
        # result = list(checkip.curl_multi_test(cname=customer, cpass=form.userpass.data, website=form.checkurl.data)) # NOQA
        return render_template('checkip-new.html', customer=customer, result=result, user=current_user.username, form=form) # noqa
    return render_template('checkip-new.html', customer=customer, user=current_user.username, form=form) # NOQA


@app.route('/changepass/<username>', methods=['GET', 'POST'])
@login_required
def changepass(username):
    error = ''
    form = ChangepassForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=username).first_or_404()
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('users'))
    else:
        if request.method == 'POST':
            error = 'Empty or not valid input'
        return render_template('changepass.html', username=username, form=form, error=error) # NOQA
    return render_template('changepass.html', username=username, form=form)


@app.route('/index')
@login_required
def index():
    return render_template('index.html', user=current_user.username) # NOQA


@app.route('/ipinventory', methods=['GET', 'POST'])
@login_required
def ipinventory():
    ipinv = {}
    ipinvcgn = {}
    with open('%s/data/ipsinvent.pic' % pwd, 'rb') as handle:
        ipinv = cPickle.load(handle)
    with open('%s/data/ipsinventcgn.pic' % pwd, 'rb') as handle:
        ipinvcgn = cPickle.load(handle)
    with open('%s/data/ipsinvent_europe.pic' % pwd, 'rb') as handle:
        ipsinvent_europe = cPickle.load(handle)
    with open('%s/data/ipsinvent_nordic.pic' % pwd, 'rb') as handle:
        ipsinvent_nordic = cPickle.load(handle)
    with open('%s/data/ipsinvent_n_america.pic' % pwd, 'rb') as handle:
        ipsinvent_n_america = cPickle.load(handle)
    with open('%s/data/ipsinvent_s_america.pic' % pwd, 'rb') as handle:
        ipsinvent_s_america = cPickle.load(handle)
    with open('%s/data/ipsinvent_asia.pic' % pwd, 'rb') as handle:
        ipsinvent_asia = cPickle.load(handle)
    with open('%s/data/ripeips.pic' % pwd, 'rb') as handle:
        ripeips = cPickle.load(handle)
    with open('%s/data/ripesubnets.pic' % pwd, 'rb') as handle:
        ripesubnets = cPickle.load(handle)
    countips = 0
    countipscgn = 0
    for out in ipinv:
        countips = countips + out['free_ips']
    for out in ipinvcgn:
        countipscgn = countipscgn + out['free_ips']
    # ipinv = mysql.ipinventory()
    # ipinvcgn = mysql.ipinventorycgn()

    form = getipForm()

    with open('%s/data/ipdb_customers.pic' % pwd, 'rb') as handle:
        ipdbc = cPickle.load(handle)

    form.ipdbname.choices = [(s, s) for s in ipdbc]
    form.ipdbname.choices.insert(0, ("none", "none"))

    if form.validate_on_submit():

        ips = getip.get_ip(noresilans=form.noresilans.data, provider=form.provider.data, maxpercnet=form.geomaxpercnet.data, count=form.countips.data, customer=form.ipdbname.data, geo=form.cc.data, get_ip='/home/github/ipdb/cli/get_ip.pl', iptype=form.iptype.data) # NOQA

        count = len(ips.split())
        return render_template('cc_ips.html', cc=form.cc.data, count=count, ips=ips, user=current_user.username) # NOQA

    return render_template(
        'ipinvent.html',
        ipsinvent_asia=ipsinvent_asia,
        ipsinvent_s_america=ipsinvent_s_america,
        ipsinvent_n_america=ipsinvent_n_america,
        ipsinvent_nordic=ipsinvent_nordic,
        ipsinvent_europe=ipsinvent_europe,
        ripeips=ripeips,
        ripesubnets=ripesubnets,
        countips=countips,
        countipscgn=countipscgn,
        ipinv=ipinv,
        ipinvcgn=ipinvcgn,
        user=current_user.username,
        form=form
    )


@app.route('/proxy')
@login_required
def proxy():
    customers = {}
    with open('%s/data/proxy_customers.pic' % pwd, 'rb') as handle:
        customers = cPickle.load(handle)
    # customers = mysql.get_proxy_users_ips()
    return render_template('tables.html', customers=customers, user=current_user.username) # NOQA


@app.route('/ipdb', methods=['GET', 'POST'])
@login_required
def ipdb_customers():
    form = FindipForm()
    proxy_customers = {}
    customers = {}
    with open('%s/data/proxy_customers.pic' % pwd, 'rb') as handle:
        proxy_customers = cPickle.load(handle)
    with open('%s/data/ipdb_customers_ips.pic' % pwd, 'rb') as handle:
        customers = cPickle.load(handle)
    if form.validate_on_submit():
        ip = form.findip.data
        result = ipfind.findipipdb(ips_in=form.findip.data)
        return render_template('ipdb_customers.html', ip=ip, result=result, customers=customers, proxy_customers=proxy_customers, user=current_user.username, form=form) # NOQA
    return render_template('ipdb_customers.html', customers=customers, proxy_customers=proxy_customers, user=current_user.username, form=form) # NOQA


@app.route('/findip', methods=['GET', 'POST'])
@login_required
def findip():
    form = FindipForm()
    if form.validate_on_submit():
        if form.rtonly.data:
            result = ipfind.find_rtonly(ips_in=form.findip.data)
        else:
            result = ipfind.findips(ips_in=form.findip.data)
        # result = list(checkip.curl_multi_test(cname=customer, cpass=form.userpass.data, website=form.checkurl.data)) # NOQA
        return render_template('findip.html', ip=form.findip.data, result=result, user=current_user.username, form=form) # noqa
    return render_template('findip.html', user=current_user.username, form=form) # NOQA


@app.route('/ipdeliver', methods=['GET', 'POST'])
@login_required
def ipdeliver():
    ipdbc = []
    form = IpdeliverForm()
    with open('%s/data/ipdb_customers.pic' % pwd, 'rb') as handle:
        ipdbc = cPickle.load(handle)
    form.ipdbname.choices = [(s, s) for s in ipdbc]
    form.ipdbname.choices.insert(0, ("", ""))
    if form.validate_on_submit():
        result = []
        ipcount = 0
        errors = []
        if not form.ipdest.data:
            destserver = 'None'
        else:
            destserver = form.ipdest.data
        if not form.vlanid.data:
            vlanid = 'None'
        else:
            vlanid = form.vlanid.data
        if not form.sshport.data:
            sshport = 'None'
        else:
            sshport = form.sshport.data
        if vlanid == 'None' and destserver == 'None':
            errors.append('Vlan ID and Destination Server IP are empty, you must input Vlan or Destination server IP') # NOQA
        for ip in form.ipslist.data.split():
            if not validIP(ip):
                errors.append('Invalid IpV4 in IP\'s list = %s, fix it' % ip)
            ipcount += 1
        if sshport == 'None':
            errors.append('SSH port can\'t be empty, please put current ssh port number') # NOQA
        result.append('Add/Remove IP\'s = %s' % form.status.data)
        result.append('IPDB customer name = %s' % form.ipdbname.data)
        result.append('Vlan ID = %s' % vlanid)
        result.append('Destination server = %s' % destserver)
        result.append('SSH port = %s' % sshport)
        result.append('Count IP\'s for delivery = %s' % ipcount)
        listips = form.ipslist.data
        if form.status.data == 'Add':
            result.append('Add to ip_lista/ip_lista.cc = %s' % form.iplista.data) # NOQA
            resultout = dict(goal=form.status.data, ipdbcname=form.ipdbname.data, vlan=vlanid, dserver=destserver, ssh=sshport, ips=form.ipslist.data, iplista=form.iplista.data) # NOQA
        else:
            result.append('Remove IP\'s from server = %s' %form.delipserv.data) # NOQA
            result.append('Remove from ip_lista/ip_lista.cc = %s' % form.delipiplist.data) # NOQA
            resultout = dict(goal=form.status.data, ipdbcname=form.ipdbname.data, vlan=vlanid, dserver=destserver, ssh=sshport, ips=form.ipslist.data, deliplista=form.delipiplist.data, delservip=form.delipserv.data) # NOQA
        with open('%s/tmp/delivery.pic' % pwd, 'wb') as handle:
            cPickle.dump(resultout, handle)
        return render_template('ipdeliver-modal.html', user=current_user.username, listips=listips, ipdbc=ipdbc, result=result, errors=errors, form=form) # NOQA
    return render_template('ipdeliver-modal.html', user=current_user.username, ipdbc=ipdbc, form=form) # NOQA


@app.route('/selectipdeliver', methods=['GET', 'POST'])
@login_required
def selectipdeliver():

    ipdbc = []
    outips = {}
    form = SelectIpdeliverForm()

    with open('%s/data/ipdb_customers.pic' % pwd, 'rb') as handle:
        ipdbc = cPickle.load(handle)

    with open('%s/tmp/selectdeliverips.pic' % pwd, 'rb') as handle:
        outips = cPickle.load(handle)

    listips = ''
    listips = '\n'.join(outips['ips'])
    form.ipdbname.choices = [(s, s) for s in ipdbc]
    form.ipdbname.choices.insert(0, ("", ""))

    ipcount = 0
    for ip in outips['ips']:
        ipcount += 1

    if form.validate_on_submit():
        result = []
        errors = []
        if not form.ipdest.data:
            destserver = 'None'
        else:
            destserver = form.ipdest.data
        if not form.vlanid.data:
            vlanid = 'None'
        else:
            vlanid = form.vlanid.data
        if not form.sshport.data:
            sshport = 'None'
        else:
            sshport = form.sshport.data
        if vlanid == 'None' and destserver == 'None':
            errors.append('Vlan ID and Destination Server IP are empty, you must input Vlan or Destination server IP') # NOQA
        if sshport == 'None':
            errors.append('SSH port can\'t be empty, please put current ssh port number') # NOQA

        result.append('IPDB customer name = %s' % form.ipdbname.data)
        result.append('Vlan ID = %s' % vlanid)
        result.append('Destination server = %s' % destserver)
        result.append('SSH port = %s' % sshport)
        result.append('Count IP\'s for delivery = %s' % ipcount)
        result.append('Add to ip_lista/ip_lista.cc = %s' % form.iplista.data) # NOQA
        resultout = dict(goal='Add', ipdbcname=form.ipdbname.data, vlan=vlanid, dserver=destserver, ssh=sshport, ips='\r\n'.join(outips['ips']), iplista=form.iplista.data) # NOQA
        with open('%s/tmp/delivery.pic' % pwd, 'wb') as handle:
            cPickle.dump(resultout, handle)
        print(resultout)
        return render_template('selectipdeliver-modal.html', user=current_user.username, listips=listips, ipdbc=ipdbc, result=result, errors=errors, form=form) # NOQA
    return render_template('selectipdeliver-modal.html', ipcount=ipcount, listips=listips, user=current_user.username, ipdbc=ipdbc, form=form) # NOQA


@app.route('/newselectdeliver', methods=['GET', 'POST'])
@login_required
def newselectdeliver():

    if os.path.exists('%s/tmp/selectips.pic' % pwd):
        os.remove('%s/tmp/selectips.pic' % pwd)
    if os.path.exists('%s/tmp/selectdeliverips.pic' % pwd):
        os.remove('%s/tmp/selectdeliverips.pic' % pwd)

    ipdbc = []
    geoip = []

    form = SelectipForm()

    with open('%s/data/ipdb_customers.pic' % pwd, 'rb') as handle:
        ipdbc = cPickle.load(handle)
    with open('%s/data/geoip.pic' % pwd, 'rb') as handle:
        geoip = cPickle.load(handle)

    form.geo.choices = [(s, s) for s in geoip]
    form.geo.choices.insert(0, ("", ""))
    form.ipdbname.choices = [(s, s) for s in ipdbc]
    form.ipdbname.choices.insert(0, ("none", "none"))

    return render_template('selectdeliver-modal.html', user=current_user.username, geoip=geoip, ipdbc=ipdbc, form=form) # NOQA


@app.route('/backselectdeliver', methods=['GET', 'POST'])
@login_required
def backselectdeliver():

    ipdbc = []
    geoip = []

    form = SelectipForm()

    with open('%s/data/ipdb_customers.pic' % pwd, 'rb') as handle:
        ipdbc = cPickle.load(handle)
    with open('%s/data/geoip.pic' % pwd, 'rb') as handle:
        geoip = cPickle.load(handle)

    form.geo.choices = [(s, s) for s in geoip]
    form.geo.choices.insert(0, ("", ""))
    form.ipdbname.choices = [(s, s) for s in ipdbc]
    form.ipdbname.choices.insert(0, ("none", "none"))

    if os.path.exists('%s/tmp/selectips.pic' % pwd):
        with open('%s/tmp/selectips.pic' % pwd, 'rb') as handle:
            select = cPickle.load(handle)

    if form.validate_on_submit():

        geochoice = form.geo.data
        rcountips = form.countips.data
        inputcount = int(form.countips.data)
        countcnet = form.geomaxpercnet.data
        provider = form.provider.data
        noresilans = form.noresilans.data

        ips = getip.get_ip_quik(noresilans=noresilans, provider=provider, maxpercnet=form.geomaxpercnet.data, count=form.countips.data, customer=form.ipdbname.data, geo=form.geo.data, get_ip='/home/github/ipdb/cli/get_ip.pl') # NOQA

        select = {}

        if os.path.exists('%s/tmp/selectips.pic' % pwd):
            with open('%s/tmp/selectips.pic' % pwd, 'rb') as handle:
                select = cPickle.load(handle)

        ipcount = 0
        result = {}
        geochoice = form.geo.data
        result['ips'] = ips
        result['rcountips'] = rcountips
        result['countcnet'] = countcnet
        for ip in ips.split():
            ipcount += 1
        if ipcount != inputcount:
            result['nocount'] = ipcount
        else:
            result['getcount'] = ipcount

        select[geochoice] = result

        with open('%s/tmp/selectips.pic' % pwd, 'wb') as handle:
            cPickle.dump(select, handle)
        listips = []
        for key, value in select.items():
            listips += value['ips'].split()

        outips = dict(ips=listips)
        with open('%s/tmp/selectdeliverips.pic' % pwd, 'wb') as handle:
            cPickle.dump(outips, handle)

        return render_template('selectdeliver-modal.html', user=current_user.username, geoip=geoip, ipdbc=ipdbc, select=select, form=form) # NOQA
    return render_template('selectdeliver-modal.html', user=current_user.username, geoip=geoip, ipdbc=ipdbc, select=select, form=form) # NOQA


@app.route('/selectdeliver', methods=['GET', 'POST'])
@login_required
def selectdeliver():

    ipdbc = []
    geoip = []

    form = SelectipForm()

    with open('%s/data/ipdb_customers.pic' % pwd, 'rb') as handle:
        ipdbc = cPickle.load(handle)
    with open('%s/data/geoip.pic' % pwd, 'rb') as handle:
        geoip = cPickle.load(handle)

    form.geo.choices = [(s, s) for s in geoip]
    form.geo.choices.insert(0, ("", ""))
    form.ipdbname.choices = [(s, s) for s in ipdbc]
    form.ipdbname.choices.insert(0, ("none", "none"))

    if form.validate_on_submit():

        geochoice = form.geo.data
        rcountips = form.countips.data
        inputcount = int(form.countips.data)
        countcnet = form.geomaxpercnet.data
        provider = form.provider.data
        noresilans = form.noresilans.data

        ips = getip.get_ip_quik(noresilans=noresilans, provider=provider, maxpercnet=form.geomaxpercnet.data, count=form.countips.data, customer=form.ipdbname.data, geo=form.geo.data, get_ip='/home/github/ipdb/cli/get_ip.pl') # NOQA

        select = {}

        if os.path.exists('%s/tmp/selectips.pic' % pwd):
            with open('%s/tmp/selectips.pic' % pwd, 'rb') as handle:
                select = cPickle.load(handle)

        ipcount = 0
        result = {}
        geochoice = form.geo.data
        result['ips'] = ips
        result['rcountips'] = rcountips
        result['countcnet'] = countcnet
        for ip in ips.split():
            ipcount += 1
        if ipcount != inputcount:
            result['nocount'] = ipcount
        else:
            result['getcount'] = ipcount

        select[geochoice] = result

        with open('%s/tmp/selectips.pic' % pwd, 'wb') as handle:
            cPickle.dump(select, handle)
        listips = []
        for key, value in select.items():
            listips += value['ips'].split()

        outips = dict(ips=listips)
        with open('%s/tmp/selectdeliverips.pic' % pwd, 'wb') as handle:
            cPickle.dump(outips, handle)

        return render_template('selectdeliver-modal.html', user=current_user.username, geoip=geoip, ipdbc=ipdbc, select=select, form=form) # NOQA
    return render_template('selectdeliver-modal.html', user=current_user.username, geoip=geoip, ipdbc=ipdbc, form=form) # NOQA


@app.route('/startdeliver', methods=['GET', 'POST'])
@login_required
def startdeliver():

    input = {}
    exist = []

    with open('%s/tmp/delivery.pic' % pwd, 'rb') as handle:
        input = cPickle.load(handle)

    iplist = input.get('ips').split()
    goal = input.get('goal')
    vlan = input.get('vlan')
    dserver = input.get('dserver')
    port = input.get('ssh')
    customer = input.get('ipdbcname')

    try:
        exist = ipdelivery.check_exist(ips=iplist).get('94.246.90.82:22')
    except:
        exist = 'False'

    if goal == 'Add':

        if not exist:

            statuss = {}

            if send_to_slack == True:
                text = '<!here> %s started IP delivery with WEB tools (Testing)' % current_user.username # NOQA
                ipdelivery.slack_warn(slack_channel=slack_channel, webhook_url=webhook_url, user=slack_name, text=text) # NOQA

            iplistadd = input.get('iplista')

            if vlan != 'None':
                route_target = 'bond0.' + str(vlan)
            else:
                route_target = dserver

            try:
                cr01 = ipdelivery.add_cr_routes(route_target='172.31.201.1', ips=iplist) # NOQA
                statuss['cr01'] = cr01
            except BaseException:
                traceback.print_exc()
                statuss['error'] = 'Delivery aborted ! Due to the error with add routes to cr0/1' # NOQA
                return render_template('startdeliver.html', statuss=statuss, user=current_user.username) # NOQA

            try:
                core01 = ipdelivery.add_core_routes(route_target=route_target, ips=iplist) # NOQA
                statuss['core01'] = core01
            except BaseException:
                traceback.print_exc()
                statuss['error'] = 'Delivery aborted ! Due to the error with add routes to core0/1' # NOQA
                return render_template('startdeliver.html', statuss=statuss, user=current_user.username) # NOQA

            if dserver != 'None':
                try:
                    destserv = ipdelivery.add_ips(cserver=dserver, port=port, ips=iplist) # NOQA
                    statuss['addiptoserv'] = destserv.get('addiptoserv')
                    statuss['check_ips'] = destserv.get('check_ips')
                except BaseException:
                    traceback.print_exc()
                    statuss['error'] = 'Error when added IP\'s to %s destination server. But routes was added to core0/1 with no sync_routers !' % dserver # NOQA
                    return render_template('startdeliver.html', statuss=statuss, user=current_user.username) # NOQA
            else:
                statuss['addiptoserv'] = 'None'
                statuss['check_ips'] = 'None'
            if iplistadd == True:
                try:
                    addiplista = ipdelivery.add_ip_lista(cserver=dserver, port=port, ips=iplist) # NOQA
                    statuss['addtoip_lista'] = addiplista.get('addtoip_lista')
                    statuss['addtoip_lista_cc'] = addiplista.get('addtoip_lista_cc') # NOQA
                except BaseException:
                    statuss['addtoip_lista'] = 'False'
                    statuss['addtoip_lista_cc'] = 'False'
                    traceback.print_exc()
            else:
                statuss['addtoip_lista'] = 'None'
                statuss['addtoip_lista_cc'] = 'None'
            try:
                ipdbc = []
                with open('%s/data/ipdb_customers.pic' % pwd, 'rb') as handle:
                    ipdbc = cPickle.load(handle)
                add_ipdb = ipdelivery.ipdb_add(customers=ipdbc, customer=customer, ips=iplist, ipdb='/home/github/ipdb/cli/ipdb.pl', pwd=pwd) # NOQA
                statuss['addtoipdb'] = add_ipdb
            except BaseException:
                traceback.print_exc()
                statuss['addtoipdb'] = 'IP\'s was not added to IPDB customer account' # NOQA

            sync = ipdelivery.sync_routers(sync_routers='/home/github/ipdb/sync_routers/sync_routers.sh', pwd=pwd) # NOQA
            statuss['sync_routers'] = sync

            if send_to_slack == True:
                text = '%s finished IP delivery' % current_user.username # NOQA
                ipdelivery.slack_warn(slack_channel=slack_channel, webhook_url=webhook_url, user=slack_name, text=text) # NOQA

            check_routes = ipdelivery.check_dual(pwd)
            input['name'] = current_user.username
            input['ips'] = input.get('ips').split()
            ipdelivery.save_log(pwd=pwd, input=input)
            return render_template('startdeliver.html', check_routes=check_routes, statuss=statuss, user=current_user.username) # NOQA
        else:
            return render_template('startdeliver.html', exist=exist, user=current_user.username) # NOQA

    if goal == 'Remove':

        if exist:

            statussrm = {}

            if send_to_slack == True:
                text = '<!here> %s started IP delivery with WEB tools (Removing IP\'s)' % current_user.username # NOQA
                ipdelivery.slack_warn(slack_channel=slack_channel, webhook_url=webhook_url, user=slack_name, text=text) # NOQA

            iplistarm = input.get('deliplista')
            delipserv = input.get('delservip')

            if vlan != 'None':
                route_target = 'bond0.' + str(vlan)
            else:
                route_target = dserver

            try:
                rm_cr01 = ipdelivery.del_cr_routes(route_target='172.31.201.1', ips=iplist) # NOQA
                statussrm['rm_cr01'] = rm_cr01
            except BaseException:
                traceback.print_exc()
                statussrm['error'] = 'Removing IP\'s aborted ! Due to the error with removing routes from cr0/1' # NOQA
                return render_template('startdeliver.html', statussrm=statussrm, user=current_user.username) # NOQA

            try:
                rm_core01 = ipdelivery.del_core_routes(route_target=route_target, ips=iplist) # NOQA
                statussrm['rm_core01'] = rm_core01
            except BaseException:
                traceback.print_exc()
                statussrm['error'] = 'Removing IP\'s aborted ! Due to the error with remove routes from core0/1' # NOQA
                return render_template('startdeliver.html', statussrm=statussrm, user=current_user.username) # NOQA

            if dserver != 'None':
                try:
                    if delipserv == True:
                        rm_destserv = ipdelivery.del_ips(cserver=dserver, port=port, ips=iplist) # NOQA
                        statussrm['rmipfromserv'] = rm_destserv
                    else:
                        pass
                except BaseException:
                    traceback.print_exc()
                    statussrm['error'] = 'Error when removed IP\'s from %s server. Any way routes was removed from core0/1 with no sync_routers !' % dserver # NOQA
                    return render_template('startdeliver.html', statussrm=statussrm, user=current_user.username) # NOQA
            else:
                statussrm['rmipfromserv'] = 'None'

            if iplistarm == True:
                try:
                    rmiplista = ipdelivery.clear_ip_lista(cserver=dserver, port=port, ips=iplist) # NOQA
                    statussrm['rmfromip_lista'] = rmiplista.get('rmfromip_lista') # NOQA
                    statussrm['rmfromip_lista_cc'] = rmiplista.get('rmfromip_lista_cc') # NOQA
                except BaseException:
                    statussrm['rmfromip_lista'] = 'False'
                    statussrm['rmfromip_lista_cc'] = 'False'
                    traceback.print_exc()
            else:
                statussrm['rmfromip_lista'] = 'None'
                statussrm['rmfromip_lista_cc'] = 'None'

            try:
                rm_ipdb = ipdelivery.ipdb_del(customer=customer, ips=iplist, ipdb='/home/github/ipdb/cli/ipdb.pl', pwd=pwd) # NOQA
                statussrm['rmfromipdb'] = rm_ipdb
            except BaseException:
                traceback.print_exc()
                statussrm['rmfromipdb'] = 'IP\'s was not removed from IPDB customer account' # NOQA

            sync = ipdelivery.sync_routers(sync_routers='/home/github/ipdb/sync_routers/sync_routers.sh', pwd=pwd) # NOQA
            statussrm['sync_routers'] = sync

            if send_to_slack == True:
                text = '%s finished IP delivery' % current_user.username # NOQA
                ipdelivery.slack_warn(slack_channel=slack_channel, webhook_url=webhook_url, user=slack_name, text=text) # NOQA

            check_routes = ipdelivery.check_dual(pwd)
            input['name'] = current_user.username
            input['ips'] = input.get('ips').split()
            ipdelivery.save_log(pwd=pwd, input=input)
            return render_template('startdeliver.html', check_routes=check_routes, statussrm=statussrm, user=current_user.username) # NOQA
        else:
            noexist = 'IP\'s was not found on Core0/1 routers, removing IP\'s stopped' # NOQA
            return render_template('startdeliver.html', noexist=noexist, user=current_user.username) # NOQA


@app.route('/logs')
@login_required
def logs():
    items = []
    with open(delivery_log) as f:
        for line in f:
            items.append(json.loads(line))
    return render_template('logs.html', items=items, user=current_user.username) # NOQA


@app.route('/logdetail/<datetime>')
@login_required
def logdetail(datetime):
    item = {}
    ips = ''
    date = datetime
    with open(delivery_log) as f:
        for line in f:
            dict = json.loads(line)
            if dict.get('datetime') == datetime:
                item = dict
                break
    ips = '\n'.join(item['data'].get('ips'))
    return render_template('logdetail.html', date=date, item=item, ips=ips, user=current_user.username) # NOQA


@app.route('/txt/<customer>')
@login_required
def download_txt(customer):
    iplist = mysql.get_proxy_ips(customer)
    response = make_response('\n'.join(iplist))
    datetoday = datetime.datetime.now().strftime("%Y-%m-%d")
    cd = 'attachment; filename = %s_%s.txt' % (customer, datetoday)
    response.headers['Content-Disposition'] = cd
    response.mimetype = 'text/plain'
    return response


@app.route('/ipdb_cc_ipscgn/<cc>')
@login_required
def ipdb_cc_ipscgn(cc):
    list_cc_ips = mysql.ipdb_cc_listcgn(cc)
    ips = '\n'.join(list_cc_ips)
    count = 0
    for ip in list_cc_ips:
        count += 1
    return render_template('cc_ipscgn.html', cc=cc, count=count, ips=ips, user=current_user.username) # NOQA


@app.route('/ipdb_cc_ips/<cc>')
@login_required
def ipdb_cc_ips(cc):
    list_cc_ips = mysql.ipdb_cc_list(cc)
    ips = '\n'.join(list_cc_ips)
    count = 0
    for ip in list_cc_ips:
        count += 1
    return render_template('cc_ips.html', cc=cc, count=count, ips=ips, user=current_user.username) # NOQA


@app.route('/ipdb_ips/<customer>')
@login_required
def ipdb_ips(customer):
    list_ips = mysql.get_ipdb_ips(customer)
    ips = '\n'.join(list_ips)
    count = 0
    for ip in list_ips:
        count += 1
    return render_template('customer_ips.html', customer=customer, count=count, ips=ips, user=current_user.username) # NOQA


@app.route('/get_list_ips/<customer>')
@login_required
def download_ips(customer):
    iplist = mysql.get_ipdb_ips(customer)
    response = make_response('\n'.join(iplist))
    datetoday = datetime.datetime.now().strftime("%Y-%m-%d")
    cd = 'attachment; filename = %s_%s.txt' % (customer, datetoday)
    response.headers['Content-Disposition'] = cd
    response.mimetype = 'text/plain'
    return response


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))
