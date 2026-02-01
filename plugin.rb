# frozen_string_literal: true

# name: digest-open-tracker
# about: Same-domain digest open tracking pixel + async HTTP POST to external logger
# version: 2.0.2
# authors: you

# -------------------------
# CONFIG (EDIT HERE)
# -------------------------
module ::DigestOpenTrackerConfig
  ENABLED = true

  # Pixel endpoint served by Discourse on same domain:
  #   https://forum.example.com/digest/open?email_id=...&user_id=...&user_email=...
  #
  # (Optional legacy)
  #   https://forum.example.com/digest/open.gif?...

  # External logging endpoint (receives POST)
  LOG_ENDPOINT_URL = "https://ai.templetrends.com/digest_open_log.php"

  # Optional secret gate (empty = disabled). If set, pixel URL must include &s=...
  EXPECTED_SECRET = ""

  # Optional: best-effort "log once" per (email_id,user_id)
  # Not race-proof; uses PluginStore keys.
  LOG_ONCE_PER_EMAIL_USER = false

  # HTTP timeouts for logger POST (keep short)
  HTTP_OPEN_TIMEOUT_SEC = 3
  HTTP_READ_TIMEOUT_SEC = 3

  # Sidekiq retry count for the logging job:
  # 0 = closest to your PHP (swallow failures, no retry)
  JOB_RETRY_COUNT = 0

  # Extra safety: cap User-Agent/Referer/IP to 100 (like your PHP)
  MAX_LEN = 100
end

after_initialize do
  require "base64"
  require "net/http"
  require "uri"
  require "json"
  require "time"
  require_dependency "application_controller"

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

  class ::DigestOpenTrackerController < ::ApplicationController
    skip_before_action :verify_authenticity_token, raise: false
    skip_before_action :redirect_to_login_if_required, raise: false

    def show
      return render_pixel unless ::DigestOpenTrackerConfig::ENABLED

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

      # Trim inputs to fit the same spirit as VARCHAR(100)
      max = ::DigestOpenTrackerConfig::MAX_LEN
      email_id   = ::DigestOpenTracker.trunc(email_id, max)
      user_id    = ::DigestOpenTracker.trunc(user_id, max)
      user_email = ::DigestOpenTracker.trunc(user_email, max)

      ip  = ::DigestOpenTracker.trunc(request.remote_ip, max)
      ua  = ::DigestOpenTracker.trunc(request.user_agent, max)
      ref = ::DigestOpenTracker.trunc(request.referer, max)

      # Optional "log once" (best-effort, not race-proof)
      if ::DigestOpenTrackerConfig::LOG_ONCE_PER_EMAIL_USER
        key = "once:#{email_id}:#{user_id}"
        if PluginStore.get("digest_open_tracker", key)
          return render_pixel
        end
        PluginStore.set("digest_open_tracker", key, "1")
      end

      # -------------------------
      # ALWAYS return the pixel immediately
      # -------------------------
      # Async log via Sidekiq. Enqueue failures are swallowed.
      begin
        Jobs.enqueue(
          :digest_open_tracker_log,
          email_id: email_id,
          user_id: user_id,
          user_email: user_email,
          recv_useragent: ua,
          recv_user_ip: ip,
          recv_referer: ref,
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

      # discourage caching
      response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
      response.headers["Pragma"] = "no-cache"
      response.headers["Expires"] = "0"
      response.headers["X-Content-Type-Options"] = "nosniff"

      # match your PHP behavior
      response.headers["Access-Control-Allow-Origin"] = "*"

      # Send binary gif
      send_data gif, type: "image/gif", disposition: "inline"
    end
  end

  # IMPORTANT:
  # Use routes.prepend so this route is registered BEFORE Discourse's catch-all route.
  # If you use append, you can get HTTP 200 + the Discourse HTML "page not found" shell instead of your gif.
  Discourse::Application.routes.prepend do
    # ✅ No-extension endpoint (recommended for email pixels)
    get "/digest/open" => "digest_open_tracker#show"

    # (Optional) keep legacy .gif endpoint too
    get "/digest/open.gif" => "digest_open_tracker#show"
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
            "email_id"       => args["email_id"].to_s,
            "user_id"        => args["user_id"].to_s,
            "user_email"     => args["user_email"].to_s,
            "recv_useragent" => args["recv_useragent"].to_s,
            "recv_user_ip"   => args["recv_user_ip"].to_s,
            "recv_referer"   => args["recv_referer"].to_s,
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
          req["User-Agent"] = "discourse-digest-open-tracker/2.0.2"
          req.body = URI.encode_www_form(payload)

          http.request(req)
        rescue => e
          Rails.logger.warn("[digest-open-tracker] postback error: #{e.class}: #{e.message}")
        end
      end
    end
  end
end
