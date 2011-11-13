require "rubygems"
require "bundler/setup"

require "set"
require "c2dm"
require "highline"
require "sinatra/base"
require "sinatra/reloader"
require "em-websocket"


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
      notification = {
        :registration_id => "APA91bHB3EjVBG-9SB3TXYYUx-RfnAHgggn9L4dimJBjAZr1cDiB0k4Lhg9TQmLDX3aAKCuN8-5P2gh0ovL9xQd2yCn78ax-QIqo3Rh6CVxB8xnMzPNwjBguYigEtcF3h4UAfUn19DW8fHp-7y9QmzANa0So3wK3cw",
        :data => { :body => "fuga"},
      }
      c2dm = C2DM.from_auth_token(File.read("config/google_auth_token"))
      c2dm.send_notification(notification)
      return erb(:auth)
    end

    post("/touchauth") do
      @@web_socket_server.notify()
      return "ok"
    end
    
    get("/authenticated") do
      return "Authenticated! <a href='/'>Log out</a>"
    end
    
    get("/test1") do
      return erb(:auth)
    end
    
    get("/test2") do
      @@web_socket_server.notify()
      return "ok"
    end
  
end

class TouchauthWebSocketServer
    
    def initialize()
      @sockets = Set.new()
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
    
    def notify()
      for ws in @sockets
        ws.send("auth")
      end
    end
    
    def on_web_socket_open(ws)
      never_die() do
        @sockets.add(ws)
        p [:sockets, @sockets.size]
      end
    end
    
    def on_web_socket_close(ws)
      never_die() do
        @sockets.delete(ws)
        p [:sockets, @sockets.size]
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
  else
    raise("unknown action")
end
