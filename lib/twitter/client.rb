require 'faraday'
require 'multi_json'
require 'twitter/api/direct_messages'
require 'twitter/api/favorites'
require 'twitter/api/friends_and_followers'
require 'twitter/api/help'
require 'twitter/api/lists'
require 'twitter/api/oauth'
require 'twitter/api/places_and_geo'
require 'twitter/api/saved_searches'
require 'twitter/api/search'
require 'twitter/api/spam_reporting'
require 'twitter/api/suggested_users'
require 'twitter/api/timelines'
require 'twitter/api/trends'
require 'twitter/api/tweets'
require 'twitter/api/undocumented'
require 'twitter/api/users'
require 'twitter/configurable'
require 'twitter/error/client_error'
require 'twitter/error/decode_error'
require 'simple_oauth'
require 'uri'

module Twitter
  # Wrapper for the Twitter REST API
  #
  # @note All methods have been separated into modules and follow the same grouping used in {http://dev.twitter.com/doc the Twitter API Documentation}.
  # @see http://dev.twitter.com/pages/every_developer
  class Client
    include Twitter::API::DirectMessages
    include Twitter::API::Favorites
    include Twitter::API::FriendsAndFollowers
    include Twitter::API::Help
    include Twitter::API::Lists
    include Twitter::API::OAuth
    include Twitter::API::PlacesAndGeo
    include Twitter::API::SavedSearches
    include Twitter::API::Search
    include Twitter::API::SpamReporting
    include Twitter::API::SuggestedUsers
    include Twitter::API::Timelines
    include Twitter::API::Trends
    include Twitter::API::Tweets
    include Twitter::API::Undocumented
    include Twitter::API::Users
    include Twitter::Configurable

    # Initializes a new Client object
    #
    # @param options [Hash]
    # @return [Twitter::Client]
    def initialize(options={})
      Twitter::Configurable.keys.each do |key|
        instance_variable_set(:"@#{key}", options[key] || Twitter.instance_variable_get(:"@#{key}"))
      end
    end

    # Perform an HTTP DELETE request
    def delete(path, params={})
      request(:delete, path, params)
    end

    # Perform an HTTP GET request
    def get(path, params={})
      request(:get, path, params)
    end

    # Perform an HTTP POST request
    def post(path, params={})
      signature_params = params.values.any?{|value| value.respond_to?(:to_io)} ? {} : params
      Rails.logger.warn "POSTING!! path: #{path}, params: #{params}"
      request(:post, path, params, signature_params)
    end

    def multipart_post(path, params={})
      file = params.delete(:file)
      signature_params = params.values.any?{|value| value.respond_to?(:to_io)} ? {} : params
      Rails.logger.warn "MULTIPART-POSTING!! path: #{path}, params: #{params}"
      request(:multipart_post, path, params, signature_params, file)
    end

    # Perform an HTTP PUT request
    def put(path, params={})
      request(:put, path, params)
    end

  private

    # Returns a proc that can be used to setup the Faraday::Request headers
    #
    # @param method [Symbol]
    # @param path [String]
    # @param params [Hash]
    # @return [Proc]
    def request_setup(method, path, params, signature_params)
      Proc.new do |request|
        if params.delete(:bearer_token_request)
          request.headers[:authorization] = bearer_token_credentials_auth_header
          request.headers[:content_type] = 'application/x-www-form-urlencoded; charset=UTF-8'
          request.headers[:accept] = '*/*' # It is important we set this, otherwise we get an error.
        elsif params.delete(:app_auth) || !user_token?
          unless bearer_token?
            @bearer_token = token
            Twitter.client.bearer_token = @bearer_token if Twitter.client?
          end
          request.headers[:authorization] = bearer_auth_header
        elsif method == :multipart_post
          request.headers[:authorization] = oauth_auth_header(method, path, signature_params).to_s
          request.headers[:accept] = '*/*' # It is important we set this, otherwise we get an error.
          request.headers[:connection] = "Close"
          request.headers[:user_agent] = "OAuth gem v0.4.7"
        else
          request.headers[:authorization] = oauth_auth_header(method, path, signature_params).to_s
          request.headers[:content_type] = 'application/x-www-form-urlencoded;' 
          request.headers[:accept] = '*/*' # It is important we set this, otherwise we get an error.
          request.headers[:connection] = "Close"
          request.headers[:user_agent] = "OAuth gem v0.4.7"
        end
      end
    end

    def request(method, path, params={}, signature_params=params, file=nil)
      request_setup = request_setup(method, path, params, signature_params)
      if path=="/1.1/media/upload.json"
        if method == :multipart_post
          res = multipart_upload(params, file)
          raise Twitter::Error::ClientError.new("twitter video multipart-upload error: #{res.code} -- #{res.msg}, params: #{params}") unless res.code.in? ["204", "200"]
          res
        else
          res = upload_connection.send(method.to_sym, path, params, &request_setup).env
          raise Twitter::Error::ClientError.new("twitter video upload error: #{res[:response].status} -- #{res[:response].body}, params: #{params}") unless res[:response].status.in? [200,201,202]
          res
        end
      else
        connection.send(method.to_sym, path, params, &request_setup).env
      end
    rescue Faraday::Error::ClientError
      raise Twitter::Error::ClientError
    rescue MultiJson::DecodeError
      raise Twitter::Error::DecodeError
    end

    # Returns a Faraday::Connection object
    #
    # @return [Faraday::Connection]
    def connection
      @connection ||= Faraday.new(@endpoint, @connection_options.merge(:builder => @middleware))
    end

    def upload_connection
      @upload_connection ||= Faraday.new('https://upload.twitter.com',@connection_options) do |faraday|
        faraday.request  :url_encoded
        faraday.adapter :net_http
      end
    end

    def multipart_upload(params,filename)
      boundary = "00Twurl" + rand(1000000000000000000).to_s + "lruwT99"
      multipart_body = []
      file_field = 'media'

      params.each {|key, value|
        multipart_body << "--#{boundary}\r\n"
        multipart_body << "Content-Disposition: form-data; name=\"#{key}\"\r\n"
        multipart_body << "\r\n"
        multipart_body << value
        multipart_body << "\r\n"
      }

      multipart_body << "--#{boundary}\r\n"
      multipart_body << "Content-Disposition: form-data; name=\"#{file_field}\"; filename=\"#{File.basename(filename)}\"\r\n"
      multipart_body << "Content-Type: application/octet-stream\r\n"
      multipart_body << "\r\n"
      multipart_body << File.read(filename)
      multipart_body << "\r\n--#{boundary}--\r\n"

      req = Net::HTTP::Post.new('/1.1/media/upload.json', {})
      req.body = multipart_body.join
      req.content_type = "multipart/form-data, boundary=\"#{boundary}\""

      consumer =
        OAuth::Consumer.new(
          @consumer_key,
          @consumer_secret,
          :site => 'https://upload.twitter.com',
          :proxy => nil
        )
      consumer.http.use_ssl = true
      consumer.http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      access_token = OAuth::AccessToken.new(consumer, @oauth_token, @oauth_token_secret)
      req.oauth!(consumer.http, consumer, access_token)
      res = consumer.http.request(req)
    end

    # Generates authentication header for a bearer token request
    #
    # @return [String]
    def bearer_token_credentials_auth_header
      basic_auth_token = encode_value("#{@consumer_key}:#{@consumer_secret}")
      "Basic #{basic_auth_token}"
    end

    def encode_value(value)
      [value].pack("m0").gsub("\n", '')
    end

    def bearer_auth_header
      if @bearer_token.is_a?(Twitter::Token) && @bearer_token.token_type == "bearer"
        "Bearer #{@bearer_token.access_token}"
      else
        "Bearer #{@bearer_token}"
      end
    end

    def oauth_auth_header(method, path, params={})
      if path=="/1.1/media/upload.json"
        uri = URI('https://upload.twitter.com' + path)
      else
        uri = URI(@endpoint + path)
      end
      SimpleOAuth::Header.new(method, uri, params, credentials)
    end
  end
end
