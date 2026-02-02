# frozen_string_literal: true

# name: digest-open-tracker
# about: Same-domain digest open tracking pixel + async HTTP POST to external logger
# version: 2.1.0
# authors: you

module ::DigestOpenTrackerConfig
  ENABLED = true
  LOG_ENDPOINT_URL = "http://172.17.0.1:8081/digest_open_log.php"

  # Same 64-hex key as digest-report2 + PHP (needed only if you ever want to decrypt in Ruby;
  # for this design we pass token t to PHP for decrypt, but we keep it here for future.)
  TOKEN_KEY_HEX = "" # <-- PUT YOUR 64 HEX CHARS HERE (same as digest-report2 + PHP)

  EXPECTED_SECRET = "" # (unused in token mode, kept for compatibility)
  LOG_ONCE_PER_EMAIL_USER = false

  HTTP_OPEN_TIMEOUT_SEC = 3
  HTTP_READ_TIMEOUT_SEC = 3
  JOB_RETRY_COUNT = 0

  MAX_LEN = 100
  TOKEN_MAX_LEN = 2000
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
  end

  class ::DigestOpenTrackerController < ::ActionController::Base
    protect_from_forgery with: :null_session

    def show
      return render_pixel unless ::DigestOpenTrackerConfig::ENABLED
      request.format = :gif rescue nil

      # NEW: single token
      t = params[:t].to_s
      t = t.to_s[0, ::DigestOpenTrackerConfig::TOKEN_MAX_LEN]

      # Legacy params (kept so old emails don’t break)
      email_id   = params[:email_id].to_s
      user_id    = params[:user_id].to_s
      user_email = params[:user_email].to_s

      # Optional secret gate (legacy)
      expected = ::DigestOpenTrackerConfig::EXPECTED_SECRET.to_s
      if expected != ""
        provided = params[:s].to_s
        return render_pixel unless provided == expected
      end

      max = ::DigestOpenTrackerConfig::MAX_LEN

      # Trim legacy only (do NOT trim token to 100)
      email_id   = ::DigestOpenTracker.trunc(email_id, max)
      user_id    = ::DigestOpenTracker.trunc(user_id, max)
      user_email = ::DigestOpenTracker.trunc(user_email, max)

      # REAL opener metadata (from pixel request)
      client_ip  = ::DigestOpenTracker.trunc(request.remote_ip, max)
      client_ua  = ::DigestOpenTracker.trunc(request.user_agent, max)
      client_ref = ::DigestOpenTracker.trunc(request.referer, max)

      server_ip = ""
      begin
        server_ip = ::DigestOpenTracker.trunc(request.env["SERVER_ADDR"], max)
      rescue StandardError
        server_ip = ""
      end

      # Optional "log once": in token mode use token as identity (no decrypt needed)
      if ::DigestOpenTrackerConfig::LOG_ONCE_PER_EMAIL_USER
        id_part = t.empty? ? "#{email_id}:#{user_id}" : t
        key = "once:#{id_part.to_s[0, 1800]}"
        if PluginStore.get("digest_open_tracker", key)
          return render_pixel
        end
        PluginStore.set("digest_open_tracker", key, "1")
      end

      # Async log via Sidekiq (send token to PHP; PHP will decrypt and store email/user_id/email_id)
      begin
        Jobs.enqueue(
          :digest_open_tracker_log,
          t: t,

          # legacy fallback
          email_id: email_id,
          user_id: user_id,
          user_email: user_email,

          # real opener fields
          client_user_ip: client_ip,
          client_useragent: client_ua,
          client_referer: client_ref,

          # server hop/debug fields
          discourse_server_ip: server_ip,
          discourse_postback_ua: "discourse-digest-open-tracker/2.1.0",

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

  Discourse::Application.routes.prepend do
    get "/digest/open" => "digest_open_tracker#show",
        defaults: { format: "gif" },
        constraints: { format: /(gif|html|js|json)?/ }

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
            # NEW token (preferred)
            "t" => args["t"].to_s,

            # legacy fallback
            "email_id"   => args["email_id"].to_s,
            "user_id"    => args["user_id"].to_s,
            "user_email" => args["user_email"].to_s,

            # real opener metadata
            "client_user_ip"   => args["client_user_ip"].to_s,
            "client_useragent" => args["client_useragent"].to_s,
            "client_referer"   => args["client_referer"].to_s,

            # server hop/debug
            "discourse_server_ip"   => args["discourse_server_ip"].to_s,
            "discourse_postback_ua" => args["discourse_postback_ua"].to_s,

            # extra
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
          req["User-Agent"] = "discourse-digest-open-tracker/2.1.0"
          req.body = URI.encode_www_form(payload)

          http.request(req)
        rescue => e
          Rails.logger.warn("[digest-open-tracker] postback error: #{e.class}: #{e.message}")
        end
      end
    end
  end
end
