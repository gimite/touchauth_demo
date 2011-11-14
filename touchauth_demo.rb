require "rubygems"
require "bundler/setup"

require "set"
require "c2dm"
require "highline"
require "sinatra/base"
require "sinatra/reloader"
require "em-websocket"
require "json"
require "kyotocabinet"
require "securerandom"
require "digest/sha1"
require "erb"


class TouchauthWebServer < Sinatra::Base
    
    include(ERB::Util)
    
    SESSION_SECRET_PATH = "config/session_secret"
    
    def self.web_socket_server=(serv)
      @@web_socket_server = serv
    end
    
    set(:port, 19001)
    
    if !File.exist?(SESSION_SECRET_PATH)
      open(SESSION_SECRET_PATH, "w"){ |f| f.write(SecureRandom.base64()) }
    end
    SESSION_SECRET = File.read(SESSION_SECRET_PATH)

    configure(:development) do
      #register(Sinatra::Reloader)
    end

    get("/") do
      @browser_key = request.cookies["touchauth_browser_key"]
      session = request.cookies["touchauth_session"]
      @user = nil
      if session
        (user_id, timestamp, digest) = session.split(/:/)
        if digest == Digest::SHA1.hexdigest([user_id, timestamp, SESSION_SECRET].join(":"))
          @user = Store.get(User.new(user_id))
        end
      end
      return erb(:index)
    end

    post("/login") do
      browser_key = request.cookies["touchauth_browser_key"]
      browser = browser_key && Store.get(Browser.new(browser_key))
      if browser
        user = Store.get(User.new(browser.user_id))
        p user
        notification = {
          :registration_id => user.registration_id,
          :data => {:browser_key => browser_key},
        }
        p [:note, notification]
        c2dm = C2DM.from_auth_token(File.read("config/google_auth_token"))
        c2dm.send_notification(notification)
      end
      @params_json = JSON.dump({"browserKey" => browser && browser.browser_key})
      return erb(:login)
    end
    
    get("/qr_login") do
      return erb(:qr_login)
    end

    post("/auth") do
      user = Store.get(User.new(params[:user]))
      if !user || user.mobile_key != params[:mobile_key]
        p "mobile_key mismatch"
        return "bad"
      end
      case params[:type]
        when "touch"
          browser = Store.get(Browser.new(params[:browser_key]))
          if !browser || browser.user_id != user.id
            p "browser_key mismatch"
            return "bad"
          end
        when "qr"
          Store.put(Browser.new(params[:browser_key], params[:user]))
        else
          return "unknown type"
      end
      timestamp = Time.now.to_i()
      digest = Digest::SHA1.hexdigest([params[:user], timestamp, SESSION_SECRET].join(":"))
      session = [params[:user], timestamp, digest].join(":")
      @@web_socket_server.send(
          "/auth/%s" % params[:browser_key],
          {"status" => "success", "session" => session})
      return "ok"
    end
    
    get("/authenticated") do
      return "Authenticated! <a href='/'>Log out</a>"
    end
    
    post("/signup") do
      @params_json = JSON.dump({"user" => params[:user]})
      if valid_user?(params[:user])
        return erb(:signup)
      else
        return "Invalid user ID. Only alphabet/numbers are allowed."
      end
    end
    
    post("/mobile_signup") do
      p [:signup, params[:user], params[:mobile_key], params[:browser_key], params[:registration_id]]
      if valid_user?(params[:user])
        # TODO dup check
        Store.put(User.new(params[:user], params[:mobile_key], params[:registration_id]))
        Store.put(Browser.new(params[:browser_key], params[:user]))
        return "ok"
      else
        return "Invalid user ID. Only alphabet/numbers are allowed."
      end
    end
    
    get("/test1") do
      return erb(:auth)
    end
    
    get("/test2") do
      @@web_socket_server.send()
      return "ok"
    end
    
    def valid_user?(user)
      return user =~ /\A[a-zA-Z0-9]+\z/
    end
  
end

class TouchauthWebSocketServer
    
    def initialize()
      @sockets = {}
    end
    
    def schedule()
      EventMachine.schedule() do
        port = 19002
        EventMachine::WebSocket.start(:host => "0.0.0.0", :port => port) do |ws|
          ws.onopen(){ on_web_socket_open(ws) }
          ws.onclose(){ on_web_socket_close(ws) }
          ws.onmessage(){ |m| on_web_socket_message(ws, m) }
          ws.onerror(){ |r| on_web_socket_error(ws, r) }
        end
        # TODO handle timeout
        puts("WebSocket Server is running: port=%d" % port)
      end
    end
    
    def send(path, message)
      ws = @sockets[path]
      p [:send, ws ? true : false]
      ws.send(JSON.dump(message)) if ws
    end
    
    def on_web_socket_open(ws)
      never_die() do
        # TODO close old socket
        @sockets[web_socket_path(ws)] = ws
        p [:sockets, @sockets.keys]
      end
    end
    
    def web_socket_path(ws)
      return URI.parse(ws.request["path"]).path
    end
    
    def on_web_socket_close(ws)
      never_die() do
        @sockets.delete(web_socket_path(ws))
        p [:sockets, @sockets.keys]
      end
    end
    
    def on_web_socket_message(ws, m)
      never_die() do
      end
    end
    
    def on_web_socket_error(ws, r)
      never_die() do
        p :wserror
      end
    end
    
    def never_die(&block)
      begin
        yield()
      rescue => ex
        print_backtrace(ex)
      end
    end
    
    def print_backtrace(ex)
      $stderr.puts("%s: %s (%p)" % [ex.backtrace[0], ex.message, ex.class])
      for s in ex.backtrace[1..-1]
        $stderr.puts("        %s" % s)
      end
    end

end


class Store
    
    def self.open()
      @db = KyotoCabinet::DB.new()
      check(@db.open("db/casket.kch", KyotoCabinet::DB::OWRITER | KyotoCabinet::DB::OCREATE))
    end
    
    def self.get(entry)
      value = @db[key(entry)]
      return value ? Marshal.load(value) : nil
    end
    
    def self.put(entry)
      @db[key(entry)] = Marshal.dump(entry)
    end
    
    def self.remove(entry)
      @db.remove(key(entry))
    end
    
    def self.key(entry)
      return Marshal.dump([entry.class.name, entry.key])
    end
    
    def self.dump()
      for key, value in @db
        p [Marshal.load(key), Marshal.load(value)]
      end
    end
    
    def self.check(result)
      raise("DB error: %s" % @db.error) if !result
    end
    
    open()
    
end

class User
    
    def initialize(id, mobile_key = nil, registration_id = nil)
      @id = id
      @mobile_key = mobile_key
      @registration_id = registration_id
    end
    
    attr_reader(:id, :mobile_key, :registration_id)
    
    def key
      return @id
    end
    
end


class Browser
    
    def initialize(browser_key, user_id = nil)
      @browser_key = browser_key
      @user_id = user_id
    end
    
    attr_reader(:browser_key, :user_id)
    
    def key
      return @browser_key
    end
    
end


case ARGV[0]
  when "auth"
    password = HighLine.new().ask("Password: "){ |q| q.echo = false }
    c2dm = C2DM.authenticate("gimite@gmail.com", password)
    open("config/google_auth_token", "w", 0600) do |f|
      f.write(c2dm.auth_token)
    end
  when "server"
    wsserv = TouchauthWebSocketServer.new()
    wsserv.schedule()
    TouchauthWebServer.web_socket_server = wsserv
    TouchauthWebServer.run!()
  when "test"
    Store.put(User.new("gimite", "hoge"))
    p Store.get(User.new("gimite"))
  when "dump_store"
    Store.dump()
  else
    raise("unknown action")
end

