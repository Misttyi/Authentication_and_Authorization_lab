from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import secrets
from http.cookies import SimpleCookie
import html
import time

sessions = {}
users = {
    "1":{
        "username":"Alice",
        "email":"alice@example.com",
        "role":"user"
    },
    "2":{
        "username":"Bob",
        "email":"bob@example.com",
        "role":"admin"
    }
}

accounts = {
    "Alice":{"password":"123456","user_id":"1"},
    "Bob":{"password":"654321","user_id":"2"}
}

class AuthHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/login":
            #返回登录页面
            response_html = f"""
            <h1>用户登录</h1>

            <form method="POST" action="/login">
                <input type="text" name="username" placeholder="用户名">
                <input type="password" name="password" placeholder="密码">
                <button type="submit">登录</button>
            </form>
            """
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(response_html.encode("utf-8"))
        elif path == "/profile":
            cookie_header = self.headers.get("Cookie", "")

            cookies = SimpleCookie()
            cookies.load(cookie_header)

            if "session_id" in cookies:
                session_id = cookies["session_id"].value
            else:
                session_id = ""
                self.send_response(401)
                self.end_headers()
                return
            session = sessions.get(session_id)
            if session is None:
                self.send_response(401)
                self.end_headers()
                return
            elif time.time() >= session["expires_at"]:
                sessions.pop(session_id, None)
                self.send_response(401)
                self.end_headers()
                return
            else:
                username = session["username"]

                safe_username = html.escape(username)
                profile_html = f"""
                <h1>欢迎回来，{safe_username}!</h1>
                
                <form method="POST" action="/logout">
                    <button type="submit">退出登录</button>
                </form>
                """
                self.send_response(200)
                self.send_header("Content-Type","text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(profile_html.encode("utf-8"))
                return 
        elif path.startswith("/users/"):
            user_id = path.split("/")[-1]
            user = users.get(user_id)
            if user is None:
                self.send_response(404)
                self.end_headers()
                return
            else:
                cookie_header = self.headers.get("Cookie", "")
                
                cookies = SimpleCookie()
                cookies.load(cookie_header)
                if "session_id" not in cookies:
                    self.send_response(401)
                    self.end_headers()
                    return

                session_id = cookies["session_id"].value
    
                session = sessions.get(session_id)
    
                if session is None:
                    self.send_response(401)
                    self.end_headers()
                    return 
                if time.time() >= session["expires_at"]:
                    sessions.pop(session_id,None)
                    self.send_response(401)
                    self.end_headers()
                    return
                if session["user_id"] != user_id:
                    self.send_response(403)
                    self.end_headers()
                    return
                
                self.send_response(200)
                safe_username = html.escape(user["username"])
                safe_email = html.escape(user["email"])
                email_html = f"{safe_username} : {safe_email}"
                self.send_header("Content-Type","text/html;charset=utf-8")
                self.end_headers()
                self.wfile.write(email_html.encode("utf-8"))
                return
        elif path == "/admin":
            cookie_header = self.headers.get("Cookie","")
            cookies = SimpleCookie()
            cookies.load(cookie_header)
            if "session_id" not in cookies:
                self.send_response(401)
                self.end_headers()
                return

            session_id = cookies["session_id"].value
            session = sessions.get(session_id)  
            if session is None:
                self.send_response(401)
                self.end_headers()
                return
            if time.time() >= session["expires_at"]:
                sessions.pop(session_id,None)
                self.send_response(401)
                self.end_headers()
                return      
            user_id = session.get("user_id")
            user = users.get(user_id)
            if user is None:
                self.send_response(403)
                self.end_headers()
                return
                
            if user["role"] != "admin":
                self.send_response(403)
                self.end_headers()
                return
            
            admin_html = f"""
            <h1>管理员控制台</h1>
            <p>这里是只有管理员才能访问的页面</p>
            """
            self.send_response(200)
            self.send_header("Content-Type","text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(admin_html.encode("utf-8"))

        else:
            self.send_response(404)
            self.end_headers()
            return
        

    def do_POST(self):
        path = urlparse(self.path).path

        if path == "/login":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            data = parse_qs(body)
            username = data.get("username",[""])[0]
            password = data.get("password",[""])[0]
            account = accounts.get(username)

            if account is not None and password == account["password"]:
                user_id = account["user_id"]
                role = users[user_id]["role"]
                session_id  = secrets.token_hex(32)
                sessions[session_id] = {
                    "username":username,
                    "expires_at":time.time() + 60,
                    "user_id": user_id,
                    "role":role
                }
                print("登陆成功,当前会话数量：",len(sessions))
                self.send_response(303)
                self.send_header("Set-Cookie",f"session_id={session_id};HttpOnly;SameSite=Lax;Path=/")
                self.send_header("Location", "/profile")
                self.end_headers()

            else:
                print("登陆失败")
                self.send_response(401)
                self.end_headers()
        elif path == "/logout":
            cookie_header = self.headers.get("Cookie", "")

            cookies = SimpleCookie()
            cookies.load(cookie_header)
            if "session_id" not in cookies:
                self.send_response(401)
                self.end_headers()
                return

            session_id = cookies["session_id"].value

            session = sessions.get(session_id)

            if session is None:#保证只有登录用户才能退出
                self.send_response(401)
                self.end_headers()
                return 
            if time.time() >= session["expires_at"]:
                sessions.pop(session_id,None)
                self.send_response(401)
                self.end_headers()
                return
            sessions.pop(session_id, None)
            
            self.send_response(303)
            self.send_header("Set-Cookie",
                             "session_id=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0")
            self.send_header("Location", "/login")
            self.end_headers()

        else:
            self.send_response(404)
            self.end_headers()


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 8006), AuthHandler)
    print("身份认证实验服务器：http://127.0.0.1:8006")
    server.serve_forever()