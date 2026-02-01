# frozen_string_literal: true

# name: digest-open-tracker
# about: Same-domain digest open tracking pixel + async HTTP POST to external logger
# version: 2.0.5
# authors: you

# -------------------------
# CONFIG (EDIT HERE)
# -------------------------
module ::DigestOpenTrackerConfig
  ENABLED = true

  # External logging endpoint (receives POST)
  LOG_ENDPOINT_URL = "https://ai.templetrends.com/digest_open_log.php"

  # Optional secret gate (empty = disabled). If set, pixel URL must include &s=...
  EXPECTED_SECRET = ""

  # Optional: best-effort "log once" per (email_id,user_id)
  LOG_ONCE_PER_EMAIL_USER = false

  # HTTP timeouts for logger POST (keep short)
  HTTP_OPEN_TIMEOUT_SEC = 3
  HTTP_READ_TIMEOUT_SEC = 3

  # Sidekiq retry count for the logging job:
  # 0 = closest to your PHP (swallow failures, no retry)
  JOB_RETRY_COUNT = 0

  # Extra safety: cap User-Agent/Referer/IP to 100
  MAX_LEN = 100
end

after_initialize do
  require "base64"
  require "net/http"
  require "uri"
  require "json"
  require "time"

  module ::DigestOpenTracker
    GIF_1X1 = Base64.decode64("R0lGODlhAQABAPAAAAAAAAAAACH5BAEAAAAALAAAAAABAAEAAAICRAEAOw==").freeze

    def self.trunc(s, n)
      s.to_s[0, n]
    end

    # constant-time compare (best-effort)
    def self.secure_equals(a, b)
      a = a.to_s
      b = b.to_s
      return false if a.bytesize != b.bytesize
      r = 0
      a.bytes.zip(b.bytes) { |x, y| r |= (x ^ y) }
      r == 0
    end
  end

  # IMPORTANT: plain Rails controller base to avoid Discourse HTML stack
  class ::DigestOpenTrackerController < ::ActionController::Base
    protect_from_forgery with: :null_session

    def show
      return render_pixel unless ::DigestOpenTrackerConfig::ENABLED

      request.format = :gif rescue nil

      # -------------------------
      # Read params (GET only) - NO validation / NO checks
      # -------------------------
      email_id   = params[:email_id].to_s
      user_id    = params[:user_id].to_s
      user_email = params[:user_email].to_s

      # Optional secret gate (not input validation)
      expected = ::DigestOpenTrackerConfig::EXPECTED_SECRET.to_s
      if expected != ""
        provided = params[:s].to_s
        return render_pixel unless ::DigestOpenTracker.secure_equals(expected, provided)
      end

      # Trim inputs to fit VARCHAR(100)
      max = ::DigestOpenTrackerConfig::MAX_LEN
      email_id   = ::DigestOpenTracker.trunc(email_id, max)
      user_id    = ::DigestOpenTracker.trunc(user_id, max)
      user_email = ::DigestOpenTracker.trunc(user_email, max)

      # REAL opener metadata (from the pixel request)
      client_ip  = ::DigestOpenTracker.trunc(request.remote_ip, max)
      client_ua  = ::DigestOpenTracker.trunc(request.user_agent, max)
      client_ref = ::DigestOpenTracker.trunc(request.referer, max)

      # Optional: Discourse/server hop metadata (useful for debugging)
      server_ip = ""
      begin
        server_ip = ::DigestOpenTracker.trunc(request.env["SERVER_ADDR"], max)
      rescue StandardError
        server_ip = ""
      end

      # Optional "log once" (best-effort, not race-proof)
      if ::DigestOpenTrackerConfig::LOG_ONCE_PER_EMAIL_USER
        key = "once:#{email_id}:#{user_id}"
        if PluginStore.get("digest_open_tracker", key)
          return render_pixel
        end
        PluginStore.set("digest_open_tracker", key, "1")
      end

      # ALWAYS return pixel immediately; async log via Sidekiq
      begin
        Jobs.enqueue(
          :digest_open_tracker_log,
          email_id: email_id,
          user_id: user_id,
          user_email: user_email,

          # Real opener fields
          client_user_ip: client_ip,
          client_useragent: client_ua,
          client_referer: client_ref,

          # Server hop/debug fields
          discourse_server_ip: server_ip,
          discourse_postback_ua: "discourse-digest-open-tracker/2.0.5",

          forum_host: request.host.to_s,
          forum_base_url: Discourse.base_url.to_s,
          ts_utc: Time.now.utc.iso8601
        )
      rescue => e
        Rails.logger.warn("[digest-open-tracker] enqueue failed: #{e.class}: #{e.message}")
      end

      render_pixel
    rescue => e
      Rails.logger.warn("[digest-open-tracker] controller error: #{e.class}: #{e.message}")
      render_pixel
    end

    private

    def render_pixel
      gif = ::DigestOpenTracker::GIF_1X1

      response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
      response.headers["Pragma"] = "no-cache"
      response.headers["Expires"] = "0"
      response.headers["X-Content-Type-Options"] = "nosniff"
      response.headers["Access-Control-Allow-Origin"] = "*"
      response.headers["Content-Length"] = gif.bytesize.to_s

      response.status = 200
      response.content_type = "image/gif"
      self.response_body = gif
    end
  end

  # CRITICAL: prepend + default gif format so it always hits this controller cleanly
  Discourse::Application.routes.prepend do
    get "/digest/open"     => "digest_open_tracker#show",
        defaults: { format: "gif" },
        constraints: { format: /(gif|html|js|json)?/ }

    # optional legacy
    get "/digest/open.gif" => "digest_open_tracker#show",
        defaults: { format: "gif" }
  end

  module ::Jobs
    class DigestOpenTrackerLog < ::Jobs::Base
      sidekiq_options retry: ::DigestOpenTrackerConfig::JOB_RETRY_COUNT

      def execute(args)
        return unless ::DigestOpenTrackerConfig::ENABLED

        endpoint = ::DigestOpenTrackerConfig::LOG_ENDPOINT_URL.to_s
        return if endpoint.strip == ""

        begin
          uri = URI.parse(endpoint)

          payload = {
            "email_id"   => args["email_id"].to_s,
            "user_id"    => args["user_id"].to_s,
            "user_email" => args["user_email"].to_s,

            # Real opener (IMPORTANT)
            "client_user_ip"   => args["client_user_ip"].to_s,
            "client_useragent" => args["client_useragent"].to_s,
            "client_referer"   => args["client_referer"].to_s,

            # Server hop/debug
            "discourse_server_ip" => args["discourse_server_ip"].to_s,
            "discourse_postback_ua" => args["discourse_postback_ua"].to_s,

            # Extra fields
            "forum_host"     => args["forum_host"].to_s,
            "forum_base_url" => args["forum_base_url"].to_s,
            "ts_utc"         => args["ts_utc"].to_s
          }

          http = Net::HTTP.new(uri.host, uri.port)
          http.use_ssl = (uri.scheme == "https")
          http.open_timeout = ::DigestOpenTrackerConfig::HTTP_OPEN_TIMEOUT_SEC
          http.read_timeout = ::DigestOpenTrackerConfig::HTTP_READ_TIMEOUT_SEC

          req = Net::HTTP::Post.new(uri.request_uri)
          req["Content-Type"] = "application/x-www-form-urlencoded"
          req["User-Agent"] = "discourse-digest-open-tracker/2.0.5"
          req.body = URI.encode_www_form(payload)

          http.request(req)
        rescue => e
          Rails.logger.warn("[digest-open-tracker] postback error: #{e.class}: #{e.message}")
        end
      end
    end
  end
end
