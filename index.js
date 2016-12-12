var HYRWEB = new Vue({
  el: '#hyrweb',
  data: {
    loggingIn: false,
    logins: [],
    username: null,
    password: null,
    sessions: [
      {
        name: '登录',
        _active: false,
        _login: true
      }
    ],
    ws: null,
    types: {
      '定利宝3年返还': {
        type: 'dtpay',
        id: 106,
        pattern: 2
      },
      '定利宝3年复投': {
        type: 'dtpay',
        id: 106,
        pattern: 1
      },
      '定利宝2年返还': {
        type: 'dtpay',
        id: 105,
        pattern: 2
      },
      '定利宝2年复投': {
        type: 'dtpay',
        id: 105,
        pattern: 1
      },
      '定利宝年半返还': {
        type: 'dtpay',
        id: 104,
        pattern: 2
      },
      '定利宝年半复投': {
        type: 'dtpay',
        id: 104,
        pattern: 1
      },
      '定利宝1年返还': {
        type: 'dtpay',
        id: 103,
        pattern: 2
      },
      '定利宝1年复投': {
        type: 'dtpay',
        id: 103,
        pattern: 1
      },
      '定利宝半年返还': {
        type: 'dtpay',
        id: 102,
        pattern: 2
      },
      '定利宝半年复投': {
        type: 'dtpay',
        id: 102,
        pattern: 1
      },
      '定利宝半年复投': {
        type: 'dtpay',
        id: 102,
        pattern: 1
      },
      '随易投15天': {
        type: 'suiyitou',
        id: 193,
        pattern: 0
      },
      '随易投29天': {
        type: 'suiyitou',
        id: 194,
        pattern: 0
      }
    }
  },
  watch: {
    sessions: {
      handler: function () {
        localStorage.setItem('sessions', JSON.stringify(_(this.sessions).filter(function (s) {
          return !s._login;
        }).map(function (s) {
          return _.pick(s, ['session', 'user', 'userid', 'token', 'name', 'type', 'amount', '_active']);
        })));
      },
      deep: true
    }
  },
  methods: {
    getTypeName: function (cond) {
      return _.findKey(this.types, cond);
    },
    setTabActive: function (target) {
      for (var i = this.sessions.length - 1; i > -1; i--) {
        this.sessions[i]._active = _.eq(this.sessions[i], target);
      }
    },
    newLogin: function () {
      this.logins = [];
      this.moreLogin();
    },
    crackCaptcha: function (login) {
      if (login.captcha) return;
      login._cracking = true;
      this.$http.post('/crack', { image: login.image }).then(function (res) {
        login.captcha = res.body.result;
      }).finally(function () {
        login._cracking = false;
      });
    },
    moreLogin: function (replace) {
      this.$http.get('/new').then(function (res) {
        var login = {
          _cracking: false,
          image: res.body.image,
          session: res.body.session,
          captcha: null
        };
        if (+replace >= 0) {
          _.merge(this.logins[+replace], login);
        } else {
          this.logins.push(login);
        }
      }.bind(this));
    },
    login: function () {
      this.loggingIn = true;
      var promises = _.map(this.logins, function (login) {
        return this.$http.post('/login', {
          username: this.username,
          password: this.password,
          captcha: login.captcha,
          session: login.session
        })
      }.bind(this));
      Q.all(promises).then(function (ress) {
        this.username = null;
        this.password = null;
        this.newLogin();
        _.each(ress, function (res) {
          this.newSession(res.body);
        }.bind(this));
      }.bind(this), function (res) {
        alert(res.body.message);
      }).finally(function () {
        this.loggingIn = false;
      }.bind(this));
    },
    logout: function (session) {
      this.username = session.name;
      this.password = null;
      for (var i = this.sessions.length - 1; i > -1; i--) {
        if (_.eq(this.sessions[i], session)) {
          this.sessions.splice(i, 1);
        }
      }
      this.setTabActive(_.last(this.sessions));
    },
    getInfo: function (session) {
      session.info = [];
      session.records = [];
      this.$http.post('/info', {
        session: session.session
      }).then(function (res) {
        var info = res.body.info;
        var name = _.find(info, { key: '用户名' });
        if (name) {
          session.name = name.value;
        } else {
          session._expired = true;
          return;
        }
        session.info = info;
        session.records = res.body.records || [];
      }.bind(this));
    },
    newSession: function (obj) {
      if (!obj) return;
      var session = {
        session: obj.session,
        user: obj.user,
        userid: obj.userid,
        token: obj.token,
        name: obj.name || obj.session,
        info: [],
        records: [],
        type: obj.type || this.types[_(this.types).keys().first()],
        amount: obj.amount || 10000,
        _active: obj._active || false,
        _logs: [],
        _expired: false
      };
      this.sessions.splice(this.sessions.length - 1, 0, session);
      this.getInfo(session);
    },
    go: function (tab) {
      if (!this.ws) return;
      this.ws.send(JSON.stringify({
        session: tab.session,
        user: tab.user,
        userid: tab.userid,
        token: tab.token,
        type: String(tab.type.type),
        id: String(tab.type.id),
        pattern: String(tab.type.pattern),
        amount: String(tab.amount)
      }));
    },
    ungo: function (tab) {
      if (!this.ws) return;
      this.ws.send(JSON.stringify({
        session: tab.session,
        action: 'stop'
      }));
    },
    allDo: function (func) {
      _(this.sessions).filter(function (s) { return !s._login; }).each(func);
    },
    allGo: function () {
      this.allDo(this.go);
    },
    allStop: function () {
      this.allDo(this.ungo);
    },
    allReload: function () {
      this.allDo(this.getInfo);
    },
    allOut: function () {
      this.allDo(this.logout);
    }
  },
  created: function () {
    this.newLogin();

    this.ws = new WebSocket('ws://' + window.location.host + '/ws');
    this.ws.onopen = function (evt) {
    }.bind(this);
    this.ws.onclose = function (evt) {
      this.ws = null;
    }.bind(this);
    this.ws.onerror = function (evt) {
      this.ws = null;
    }.bind(this);
    this.ws.onmessage = function (evt) {
      var data = JSON.parse(evt.data);
      var session = _.find(this.sessions, { session: data.session });
      if (session._logs.length > 0 && session._logs[0] === '请稍候...') {
        session._logs.splice(0, 1);
      }
      session._logs.unshift(data.message);
      if (session._logs.length > 30) session._logs.length = 30;
    }.bind(this);

    try {
      var sessions = JSON.parse(localStorage.getItem('sessions'));
      _.each(sessions, this.newSession);
      this.setTabActive(_.find(this.sessions, { _active: true }) || _.last(this.sessions));
    } catch(e) {}
  }
});
