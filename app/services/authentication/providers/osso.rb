module Authentication
  module Providers
    # Osso authentication provider, uses omniauth-osso as backend.
    # Osso is an open source service for adding SAML based SSO to
    # your application. The Osso team added Osso as a provider
    # in order to serve as a real-world example of how simple it
    # is to integrate Osso.
    #
    # Learn more about Osso at https://ossoapp.com

    class Osso < Provider
      OFFICIAL_NAME = "SAML SSO".freeze
      SETTINGS_URL = "https://ossoapp.com".freeze # TODO

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

      # We're overriding these methods to add a little security with a random
      # string for state
      def self.authentication_path(state: SecureRandom.hex(32), **kwargs)
        ::Authentication::Paths.authentication_path(
          provider_name,
          state: state,
          **kwargs,
        )
      end

      # TODO: this suggests we can pass email in, rather than use hosted login
      def self.sign_in_path(state: SecureRandom.hex(32), **_kwargs)
        ::Authentication::Paths.authentication_path(
          provider_name,
          email: "sam@customer.com",
          state: state,
        )
      end

      protected

      def cleanup_payload(auth_payload)
        auth_payload
      end
    end
  end
end
