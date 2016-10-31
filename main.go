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
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/caiguanhao/gotogether"
	"github.com/gorilla/websocket"
	"github.com/skratchdot/open-golang/open"
)

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

func postLogin(username, password, captcha, inSession string) (outSession, outUserID, outToken *string, err error) {
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
	// fmt.Println(fmt.Sprintf("PHPSESSID=%s; USERID=%s; TOKEN=%s", session, userid, token))
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	defer resp.Body.Close()
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
	clients[ws] = true
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
			if _, ok := going[msg["session"]]; ok {
				delete(going, msg["session"])
			}
			continue
		}
		going[msg["session"]] = true
		go buyProduct(msg["id"], msg["pattern"], msg["amount"], []string{msg["session"], msg["userid"], msg["token"]})
	}
	ws.Close()
	if _, ok := clients[ws]; ok {
		delete(clients, ws)
	}
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
		conn.WriteMessage(websocket.TextMessage, body)
	}
}

func buyProduct(id, pattern, amount string, session_userid_token []string) {
	session := session_userid_token[0]
	for {
		if _, ok := going[session]; !ok {
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
		if _, ok := going[session]; !ok {
			break
		}
		ok, msg, verbose := send("/dtpay/Freezingorders.html", session_userid_token, url.Values{"id": {id}, "pattern": {pattern}, "money": {amount}, "coupon": {"0"}})
		// fmt.Println(verbose)
		broadcast(map[string]string{
			"session": session,
			"message": fmt.Sprintf("[%s] [购买] %s", time.Now().Format("15:04:05"), msg),
			"verbose": verbose,
		})
		if ok {
			break
		}
		time.Sleep(1 * time.Second)
	}
}

func getInfoHandler(w http.ResponseWriter, r *http.Request) {
	data, err := parseJsonRequestBody(r.Body)
	if errJson(w, err) {
		return
	}

	var records [][]string
	var info []map[string]string
	var productInfo []map[string]string
	var userInfo []map[string]string

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
				info = append(info, map[string]string{
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
				userInfo = append(userInfo, map[string]string{
					"key":   strings.Replace(td.Eq(0).Text(), "：", "", -1),
					"value": val,
				})
			})
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
					"key":   fmt.Sprintf("%s剩余", strings.TrimSpace(s.Find(".Sb_conList_month span").Text())),
					"value": fmt.Sprintf("%d%% (%s万元)", 100-done, s.Find(".Sb_conList_LastMoney strong").Text()),
				})
			})
		},
	}.Run()

	info = append(info, productInfo...)
	info = append(info, userInfo...)

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
	outSession, outUserID, outToken, err := postLogin(data["username"], data["password"], data["captcha"], data["session"])
	if errJson(w, err) {
		return
	}
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

func main() {
	port := 9876
	go func() {
		println("HYR-WEB 1.0 - Created By CGH")
		open.Run(fmt.Sprintf("http://127.0.0.1:%d/", port))
	}()
	http.HandleFunc("/ws", wsHandler)
	http.HandleFunc("/info", getInfoHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/new", newSessionHandler)
	http.HandleFunc("/index.js", func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "index.js", time.Now(), strings.NewReader(index_js))
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "index.html", time.Now(), strings.NewReader(index_html))
	})
	http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
}
