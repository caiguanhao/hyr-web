new Vue({
  el: '#hyrweb',
  computed: {
    tabs: function () {
      return _.concat(this.sessions, [
        {
          name: '登录',
          _login: true
        }
      ]);
    }
  },
  data: {
    loginImage: null,
    loginSession: null,
    username: null,
    password: null,
    captcha: null,
    activeTabIndex: 0,
    sessions: [],
    ws: null,
    types: {
      '3年返还': {
        id: 106,
        pattern: 2
      },
      '3年复投': {
        id: 106,
        pattern: 1
      },
      '2年返还': {
        id: 105,
        pattern: 2
      },
      '2年复投': {
        id: 105,
        pattern: 1
      }
    }
  },
  watch: {
    sessions: {
      handler: function () {
        localStorage.setItem('sessions', JSON.stringify(_.map(this.sessions, function (s) {
          return _.pick(s, ['session', 'userid', 'token', 'name']);
        })));
      },
      deep: true
    }
  },
  methods: {
    goLogin: function (session) {
      this.username = session.name;
      this.password = null;
      for (var i = this.sessions.length; i > -1; i--) {
        if (_.eq(this.sessions[i], session)) {
          this.sessions.splice(i, 1);
        }
      }
      this.activeTabIndex = this.sessions.length;
    },
    newLogin: function () {
      this.$http.get('/new').then(function (res) {
        this.captcha = null;
        this.loginImage = res.body.image;
        this.loginSession = res.body.session;
      }.bind(this));
    },
    login: function () {
      this.$http.post('/login', {
        username: this.username,
        password: this.password,
        captcha: this.captcha,
        session: this.loginSession
      }).then(function (res) {
        this.username = null;
        this.password = null;
        this.newLogin();
        this.newSession(res.body);
      }.bind(this), function (res) {
        alert(res.body.message);
      });
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
        this.activeTabIndex = 0;
      }.bind(this));
    },
    newSession: function (obj) {
      if (!obj) return;
      var session = {
        session: obj.session,
        userid: obj.userid,
        token: obj.token,
        name: obj.name || obj.session,
        info: [],
        records: [],
        type: this.types[_(this.types).keys().first()],
        amount: 10000,
        _logs: [],
        _expired: false
      };
      this.sessions.push(session);
      this.getInfo(session);
    },
    go: function (tab) {
      if (!this.ws) return;
      this.ws.send(JSON.stringify({
        session: tab.session,
        userid: tab.userid,
        token: tab.token,
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
      console.log(session.name, JSON.stringify(JSON.parse(data.verbose)));
      session._logs.unshift(data.message);
      if (session._logs.length > 30) session._logs.length = 30;
    }.bind(this);

    try {
      var sessions = JSON.parse(localStorage.getItem('sessions'));
      _.each(sessions, function (sess) {
        this.newSession(sess);
      }.bind(this));
    } catch(e) {}
  }
});
