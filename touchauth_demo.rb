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


class TouchauthWebServer < Sinatra::Base
    
    def self.web_socket_server=(serv)
      @@web_socket_server = serv
    end
    
    set(:port, 19001)

    get("/") do
      return erb(:index)
    end

    configure(:development) do
      register(Sinatra::Reloader)
    end

    post("/auth") do
      browser_key = request.cookies["touchauthBrowserKey"]
      browser = Store.get(Browser.new(browser_key))
      return "Browser not registered" if !browser
      user = Store.get(User.new(browser.user_id))
      p user
      notification = {
        :registration_id => user.registration_id,
        :data => {:browser_key => browser_key},
      }
      p [:note, notification]
      c2dm = C2DM.from_auth_token(File.read("config/google_auth_token"))
      c2dm.send_notification(notification)
      return erb(:auth)
    end

    post("/touchauth") do
      user = Store.get(User.new(params[:user]))
      browser = Store.get(Browser.new(params[:browser_key]))
      if !user || user.mobile_key != params[:mobile_key]
        p "mobile_key mismatch"
        return "bad"
      elsif !browser || browser.user_id != user.id
        p "browser_key mismatch"
        return "bad"
      else
        @@web_socket_server.notify("/auth/%s" % params[:browser_key])
        return "ok"
      end
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
      @@web_socket_server.notify()
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
    
    def notify(path)
      ws = @sockets[path]
      p [:notify, ws ? true : false]
      ws.send("auth") if ws
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

