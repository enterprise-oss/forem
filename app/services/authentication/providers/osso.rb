module Authentication
  module Providers
    # GitHub authentication provider, uses omniauth-github as backend
    class Osso < Provider
      OFFICIAL_NAME = "SAML SSO".freeze
      SETTINGS_URL = "https://ossapp.com".freeze # TODO

      def new_user_data
        name = info.name || info.email.to_s

        {
          email: info.email.to_s,
          name: name,
          osso_username: user_nickname
        }
      end

      def existing_user_data
        {
          email: info.email.to_s
        }
      end

      def user_email
        info.email.to_s
      end

      # We're overriding this method because Osso doesn't have a concept nickname or username.
      # Instead: we'll construct one based on the user's name with some randomization thrown in based
      # on uid, which is guaranteed to be present and unique on Facebook.
      def user_nickname
        [
          info.name.sub(" ", "_"),
          Digest::SHA512.hexdigest(payload.uid),
        ].join("_")[0...25]
      end

      def self.official_name
        OFFICIAL_NAME
      end

      def self.settings_url
        SETTINGS_URL
      end

      def self.authentication_path(state: SecureRandom.hex(32), **_kwargs)
        ::Authentication::Paths.authentication_path(
          provider_name,
          state: state,
          email: "sam@customer.com", # TODO: this means we can pass email in, rather than use hosted login
        )
      end

      # This gets used as the redirect URI, which for osso (and I think OAuth spec?)
      # can't have query params like state or code
      def self.sign_in_path(**_kwargs)
        ::Authentication::Paths.authentication_path(
          provider_name,
        )
      end

      protected

      def cleanup_payload(auth_payload)
        auth_payload
      end
    end
  end
end
