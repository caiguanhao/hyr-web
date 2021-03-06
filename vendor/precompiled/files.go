package precompiled

const File_index_html = `<!doctype html>

<html>
<head>
<meta charset="utf-8">
<title>HYR-WEB 1.7</title>
<link rel="icon" href="data:;base64,iVBORw0KGgo=">
<link href="//cdn.bootcss.com/bootstrap/3.3.7/css/bootstrap.min.css" rel="stylesheet">
<link href="//cdn.bootcss.com/bootstrap/3.3.7/css/bootstrap-theme.min.css" rel="stylesheet">
<script src="//cdn.bootcss.com/lodash.js/4.16.4/lodash.min.js"></script>
<script src="//cdn.bootcss.com/vue/2.0.3/vue.min.js"></script>
<script src="//cdn.bootcss.com/vue-resource/1.0.3/vue-resource.min.js"></script>
<script src="//cdn.bootcss.com/q.js/1.4.1/q.min.js"></script>
<style>
  .captcha {
    min-width: 180px;
    margin-bottom: 10px;
  }
  .captcha .form-control {
    padding-left: 74px;
  }
  .captcha .image {
    position: absolute;
    left: 18px;
    top: 1px;
    border-right: 1px solid #ccc;
  }
  .captcha img {
    height: 32px;
    width: 64px;
    background: #fff;
  }
</style>
</head>
<body>
  <div id="hyrweb" class="container-fluid">
    <div class="page-header">
      <h4>HYR-WEB 1.7</h4>
    </div>
    <ul class="nav nav-tabs" style="margin-bottom: 20px">
      <li v-for="tab in sessions" v-bind:class="{active: tab._active}">
        <a href v-on:click.prevent="setTabActive(tab)" v-text="tab.name"></a>
      </li>

      <li class="pull-right" v-if="sessions.length>1">
        <div class="btn-group btn-group-sm">
          <button type="button" class="btn btn-default" v-on:click="allGo()">同时开抢</button>
          <button type="button" class="btn btn-default" v-on:click="allStop()">同时停抢</button>
          <button type="button" class="btn btn-default" v-on:click="allReload()">全部刷新</button>
        </div>
      </li>
    </ul>
    <div class="tab-content">
      <div v-for="tab in sessions" v-bind:class="{active: tab._active}" class="tab-pane">
        <form v-if="tab._login === true" class="form-horizontal" v-on:submit="login()">
          <div class="form-group">
            <label for="username" class="col-sm-2 control-label">手机</label>
            <div class="col-sm-10">
              <input type="text" class="form-control" id="username" placeholder="手机" v-model="username" maxlength="11" autofocus v-bind:disabled="loggingIn">
            </div>
          </div>
          <div class="form-group">
            <label for="password" class="col-sm-2 control-label">密码</label>
            <div class="col-sm-10">
              <input type="text" class="form-control" id="password" placeholder="密码" v-model="password" maxlength="12" v-bind:disabled="loggingIn">
            </div>
          </div>
          <div class="form-group">
            <label for="captcha" class="col-sm-2 control-label">验证码</label>
            <div class="col-sm-10">
              <div class="row">
                <div class="col-sm-3 captcha" v-for="(login, index) in logins">
                  <input type="text" class="form-control" id="captcha" placeholder="验证码" v-model="login.captcha" maxlength="4">
                  <a href class="image" v-on:click.prevent="moreLogin(index)" tabindex="-1" title="点击图片更换验证码">
                    <img v-bind:src="'data:image/png;base64,'+login.image">
                  </a>
                </div>
              </div>
            </div>
          </div>
          <div class="form-group">
            <div class="col-sm-offset-2 col-sm-10">
              <div class="btn-group">
                <button type="submit" class="btn btn-default" v-bind:disabled="loggingIn" v-on:click.prevent="login()">登录</button>
                <button type="button" class="btn btn-default" v-bind:disabled="loggingIn" v-on:click="moreLogin()">增加同时登录</button>
                <button type="button" class="btn btn-default" v-bind:disabled="sessions.length<2" v-on:click="allOut()">全部退出</button>
              </div>
            </div>
          </div>
        </form>
        <div v-else>
          <div class="row">
            <div class="col-sm-8 col-md-9">
              <div class="form-horizontal" v-if="!tab._logs.length">
                <div class="form-group">
                  <label for="type" class="col-sm-1 control-label">类型</label>
                  <div class="col-sm-11">
                    <select class="form-control" id="type" v-model="tab.type">
                      <option v-for="(value, type) in types" v-text="type" v-bind:value="value"></option>
                    </select>
                  </div>
                </div>
                <div class="form-group">
                  <label for="amount" class="col-sm-1 control-label">金额</label>
                  <div class="col-sm-11">
                    <input type="text" class="form-control" id="amount" placeholder="金额" v-model="tab.amount">
                  </div>
                </div>
                <div class="form-group">
                  <label class="col-sm-1 control-label">C</label>
                  <div class="col-sm-11">
                    <div class="form-control-static" v-text="tab.challenge"></div>
                  </div>
                </div>
                <div class="form-group">
                  <label class="col-sm-1 control-label">V</label>
                  <div class="col-sm-11">
                    <div class="form-control-static" v-text="tab.validate"></div>
                  </div>
                </div>
                <div class="form-group" v-if="geetestUrl(tab)">
                  <label class="col-sm-1 control-label"></label>
                  <div class="col-sm-11">
                    <iframe v-get-validate="tab" v-bind:src="geetestUrl(tab)" width="320" height="200" frameborder="0"></iframe>
                  </div>
                </div>
                <div class="form-group">
                  <div class="col-sm-offset-1 col-sm-11">
                    <button type="button" class="btn btn-default" v-bind:disabled="!ws" v-on:click="geetest(tab)">验证</button>
                    <button type="button" class="btn btn-default" v-bind:disabled="!ws || !tab.challenge || !tab.validate" v-on:click="go(tab)">抢</button>
                  </div>
                </div>
              </div>
              <div class="form-horizontal" v-else>
                <div class="form-group">
                  <div class="col-sm-offset-1 col-sm-11">
                    <button type="button" class="btn btn-default" v-bind:disabled="!ws" v-on:click="ungo(tab)">停止抢</button>
                    <button type="button" class="btn btn-default" v-on:click="ungo(tab); tab._logs = []">停止抢并重置</button>
                  </div>
                </div>
                <div class="form-group">
                  <label for="type" class="col-sm-1 control-label">信息</label>
                  <div class="col-sm-11">
                    <div class="form-control-static">
                      类型：{{ getTypeName(tab.type) }}<br>
                      金额：{{ tab.amount }}
                    </div>
                  </div>
                </div>
                <div class="form-group">
                  <label for="type" class="col-sm-1 control-label">状态</label>
                  <div class="col-sm-11">
                    <div class="form-control-static" v-html="tab._logs.join('<br>')"></div>
                  </div>
                </div>
              </div>
              <table class="table table-stripped">
                <tbody v-if="!tab._expired && !tab.records.length">
                  <tr>
                    <td>正在获取信息...</td>
                  </tr>
                </tbody>
                <tbody v-if="tab.records.length">
                  <tr v-for="(record, index) in tab.records">
                    <th v-if="index === 0" v-for="item in record" v-bind:width="(100/record.length).toFixed(2) + '%'" v-text="item"></th>
                    <td v-if="index > 0" v-for="item in record" v-bind:colspan="record.length != tab.records[0].length ? tab.records[0].length : null" v-text="item"></td>
                  </tr>
                </tbody>
              </table>
            </div>
            <div class="col-sm-4 col-md-3">
              <table class="table table-stripped" v-if="tab.info.length">
                <thead>
                  <tr>
                    <th colspan="10">
                      <div class="btn-group">
                        <button type="button" class="btn btn-default btn-sm" v-on:click="getInfo(tab)">刷新信息</button>
                        <button type="button" class="btn btn-default btn-sm" v-on:click="logout(tab)">退出登录</button>
                      </div>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="i in tab.info">
                    <td nowrap v-text="i.key"></td>
                    <td v-text="i.value"></td>
                  </tr>
                </tbody>
              </table>
              <div v-if="!tab._expired && !tab.info.length">
                正在获取信息...
              </div>
              <div v-if="tab._expired">
                请重新
                <button class="btn btn-default btn-sm" v-on:click="logout(tab)">登录</button>
                。
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
  <script src="/index.js"></script>
</body>
</html>
`

const File_index_js = `var HYRWEB = new Vue({
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
  directives: {
    'get-validate': {
      inserted: function (el, binding) {
        el.onload = function () {
          var _appendChild = el.contentWindow.Element.prototype.appendChild;
          el.contentWindow.Element.prototype.appendChild = function () {
            var ret = _appendChild.apply(this, arguments);
            var elem = arguments[0];
            if (elem.tagName === 'SCRIPT') {
              var src = elem.getAttribute('src');
              var m = /ajax.*callback=(geetest_\d+)/.exec(src);
              if (m) {
                var cb = m[1];
                var _cb = el.contentWindow[cb];
                el.contentWindow[cb] = function () {
                  binding.value.validate = arguments[0].validate;
                  return _cb.apply(this, arguments);
                };
              }
            }
            return ret;
          };
        };
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
    moreLogin: function (replace) {
      this.$http.get('/new').then(function (res) {
        var login = {
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
        gt: null,
        challenge: null,
        validate: null,
        _active: obj._active || false,
        _logs: [],
        _expired: false
      };
      this.sessions.splice(this.sessions.length - 1, 0, session);
      this.getInfo(session);
    },
    geetest: function (tab) {
      if (!this.ws) return;
      this.ws.send(JSON.stringify({
        action: 'geetest',
        session: tab.session,
        user: tab.user,
        userid: tab.userid,
        token: tab.token
      }));
    },
    geetestUrl: function (tab) {
      if (!tab.challenge || !tab.gt || tab.validate) {
        return;
      }
      return '/geetest?success=1&challenge=' + tab.challenge + '&gt=' + tab.gt + '&debug=0&title=&mobileInfo=&lang=zh-hans-cn&width=282';
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
        amount: String(tab.amount),
        gt: String(tab.gt),
        challenge: String(tab.challenge),
        validate: String(tab.validate)
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
      if (data.type === 'geetest') {
        session.gt = data.gt;
        session.challenge = data.challenge;
        return;
      }
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
`
