# frozen_string_literal: true

# name: discourse-digest-open-pixel
# about: Same-domain digest open tracking pixel + async remote MySQL logging
# version: 1.0.1
# authors: you

# -------------------------
# CONFIG (EDIT HERE)
# -------------------------
module ::DigestOpenPixelConfig
  ENABLED = true

  # Remote MySQL (NOT local)
  MYSQL_HOST     = "ai.templetrends.com"   # e.g. "db.example.com" or "1.2.3.4"
  MYSQL_PORT     = 3306
  MYSQL_USERNAME = "root"
  MYSQL_PASSWORD = "sql1705root!@2"
  MYSQL_DATABASE = "thebox"
  MYSQL_TABLE    = "digest_open_logs_plugin"

  # Optional secret gate (empty string = disabled)
  # Pixel URL: ...&s=YOURSECRET
  EXPECTED_SECRET = ""  # e.g. "mySecret123"

  # Optional: best-effort "log once" per (email_id,user_id)
  # (No UNIQUE keys => not race-proof and requires a read)
  LOG_ONCE_PER_EMAIL_USER = false

  # MySQL timeouts (keep short so jobs don't hang)
  CONNECT_TIMEOUT_SEC = 3
  READ_TIMEOUT_SEC    = 3
  WRITE_TIMEOUT_SEC   = 3

  # Sidekiq retries for the logging job (PHP swallowed errors; retries are optional)
  # 0 = never retry (closest to your PHP)
  JOB_RETRY_COUNT = 0
end

# mysql2 native gem (requires libmysqlclient dev libs inside the container)
gem "mysql2", ">= 0.5.5"

after_initialize do
  require "base64"
  require_dependency "application_controller"

  module ::DigestOpenPixel
    GIF_1X1 = Base64.decode64("R0lGODlhAQABAPAAAAAAAAAAACH5BAEAAAAALAAAAAABAAEAAAICRAEAOw==").freeze

    def self.trunc100(s)
      s.to_s[0, 100]
    end

    # Best-effort constant-time compare
    def self.secure_equals(a, b)
      a = a.to_s
      b = b.to_s
      return false if a.bytesize != b.bytesize
      r = 0
      a.bytes.zip(b.bytes) { |x, y| r |= (x ^ y) }
      r == 0
    end

    # Create table if missing (same schema as your PHP)
    def self.create_table_if_missing!(client, table_name)
      # NOTE: mysql2 `escape` escapes strings for VALUES, not identifiers.
      # We harden table name to [A-Za-z0-9_]+ and fallback otherwise.
      safe_table = table_name.to_s
      unless safe_table.match?(/\A[a-zA-Z0-9_]+\z/)
        safe_table = "digest_open_logs"
      end

      sql = <<~SQL
        CREATE TABLE IF NOT EXISTS `#{safe_table}` (
          id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
          email_id VARCHAR(100) NULL,
          user_id VARCHAR(100) NULL,
          user_email VARCHAR(100) NULL,
          opened_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
          recv_useragent VARCHAR(100) NULL,
          recv_user_ip VARCHAR(100) NULL,
          recv_referer VARCHAR(100) NULL,
          PRIMARY KEY (id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
      SQL

      client.query(sql)
      safe_table
    end
  end

  class ::DigestOpenPixelController < ::ApplicationController
    skip_before_action :verify_authenticity_token, raise: false
    skip_before_action :redirect_to_login_if_required, raise: false

    def show
      return render_pixel unless ::DigestOpenPixelConfig::ENABLED

      # -------------------------
      # Read params (GET only) - NO checks
      # -------------------------
      email_id   = params[:email_id].to_s
      user_id    = params[:user_id].to_s
      user_email = params[:user_email].to_s

      # Optional secret gate (not input validation)
      expected = ::DigestOpenPixelConfig::EXPECTED_SECRET.to_s
      if expected != ""
        provided = params[:s].to_s
        return render_pixel unless ::DigestOpenPixel.secure_equals(expected, provided)
      end

      # Capture request metadata (trim only to fit VARCHAR(100))
      ip  = ::DigestOpenPixel.trunc100(request.remote_ip)
      ua  = ::DigestOpenPixel.trunc100(request.user_agent)
      ref = ::DigestOpenPixel.trunc100(request.referer)

      # Trim inputs to fit VARCHAR(100)
      email_id   = ::DigestOpenPixel.trunc100(email_id)
      user_id    = ::DigestOpenPixel.trunc100(user_id)
      user_email = ::DigestOpenPixel.trunc100(user_email)

      # -------------------------
      # ALWAYS return pixel immediately
      # -------------------------
      # Enqueue async logging (best-effort). Any enqueue failure is swallowed.
      begin
        Jobs.enqueue(
          :digest_open_pixel_log,
          email_id: email_id,
          user_id: user_id,
          user_email: user_email,
          recv_useragent: ua,
          recv_user_ip: ip,
          recv_referer: ref
        )
      rescue => e
        Rails.logger.warn("[digest-open-pixel] enqueue failed: #{e.class}: #{e.message}")
      end

      render_pixel
    rescue => e
      # Swallow all errors (never breaks email rendering)
      Rails.logger.warn("[digest-open-pixel] controller error: #{e.class}: #{e.message}")
      render_pixel
    end

    private

    def render_pixel
      gif = ::DigestOpenPixel::GIF_1X1

      response.headers["Content-Type"] = "image/gif"
      response.headers["Content-Length"] = gif.bytesize.to_s
      response.headers["X-Content-Type-Options"] = "nosniff"

      # discourage caching
      response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
      response.headers["Pragma"] = "no-cache"
      response.headers["Expires"] = "0"

      # match your PHP behavior
      response.headers["Access-Control-Allow-Origin"] = "*"

      render plain: gif, layout: false
    end
  end

  Discourse::Application.routes.append do
    # Same-domain pixel endpoint:
    # https://forum.example.com/digest/open.gif?email_id=...&user_id=...&user_email=...
    get "/digest/open.gif" => "digest_open_pixel#show"
  end

  module ::Jobs
    class DigestOpenPixelLog < ::Jobs::Base
      sidekiq_options retry: ::DigestOpenPixelConfig::JOB_RETRY_COUNT

      def execute(args)
        return unless ::DigestOpenPixelConfig::ENABLED

        # Swallow all errors (like your PHP)
        begin
          require "mysql2"

          client = Mysql2::Client.new(
            host: ::DigestOpenPixelConfig::MYSQL_HOST,
            port: ::DigestOpenPixelConfig::MYSQL_PORT.to_i,
            username: ::DigestOpenPixelConfig::MYSQL_USERNAME,
            password: ::DigestOpenPixelConfig::MYSQL_PASSWORD,
            database: ::DigestOpenPixelConfig::MYSQL_DATABASE,
            encoding: "utf8mb4",
            connect_timeout: ::DigestOpenPixelConfig::CONNECT_TIMEOUT_SEC,
            read_timeout: ::DigestOpenPixelConfig::READ_TIMEOUT_SEC,
            write_timeout: ::DigestOpenPixelConfig::WRITE_TIMEOUT_SEC,
            reconnect: false
          )

          table = ::DigestOpenPixel.create_table_if_missing!(client, ::DigestOpenPixelConfig::MYSQL_TABLE)

          email_id   = args["email_id"].to_s[0, 100]
          user_id    = args["user_id"].to_s[0, 100]
          user_email = args["user_email"].to_s[0, 100]
          ua         = args["recv_useragent"].to_s[0, 100]
          ip         = args["recv_user_ip"].to_s[0, 100]
          ref        = args["recv_referer"].to_s[0, 100]

          # Optional "log once" best-effort (not race-proof, does a read)
          if ::DigestOpenPixelConfig::LOG_ONCE_PER_EMAIL_USER
            check_sql = "SELECT 1 FROM `#{table}` WHERE email_id=? AND user_id=? LIMIT 1"
            stmt = client.prepare(check_sql)
            rs = stmt.execute(email_id, user_id)
            if rs&.first
              client.close rescue nil
              return
            end
          end

          insert_sql = <<~SQL
            INSERT INTO `#{table}`
              (email_id, user_id, user_email, recv_useragent, recv_user_ip, recv_referer)
            VALUES
              (?, ?, ?, ?, ?, ?)
          SQL

          stmt = client.prepare(insert_sql)
          stmt.execute(email_id, user_id, user_email, ua, ip, ref)

          client.close rescue nil
        rescue => e
          Rails.logger.warn("[digest-open-pixel] mysql log error: #{e.class}: #{e.message}")
          begin
            client.close if defined?(client) && client
          rescue
          end
        end
      end
    end
  end
end
