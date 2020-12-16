require "rails_helper"

RSpec.describe Authentication::Providers::Osso, type: :service do
  describe ".authentication_path" do
    it "returns the correct authentication path" do
      expected_path = Rails.application.routes.url_helpers.user_osso_omniauth_authorize_path
      expect(described_class.authentication_path).to start_with(expected_path)
    end

    it "supports state parameter" do
      path = described_class.authentication_path(state: "state")
      expect(path).to include("state=state")
    end

    it "provides default state parameter" do
      allow(SecureRandom).to receive(:hex).and_return("secure-state")
      path = described_class.authentication_path
      expect(path).to include("state=secure-state")
    end

    it "overrides the callback_url parameter" do
      path = described_class.sign_in_path(callback_url: "https://example.com/callback")
      expect(path).not_to include("callback_url")
    end
  end

  describe ".sign_in_path" do
    let(:expected_path) do
      "/users/auth/osso"
    end

    it "returns the correct sign in path" do
      expect(described_class.sign_in_path).to start_with(expected_path)
    end

    it "supports state parameter" do
      path = described_class.sign_in_path(state: "state")
      expect(path).to include("state=state")
    end

    it "overrides the callback_url parameter" do
      path = described_class.sign_in_path(callback_url: "https://example.com/callback")
      expect(path).not_to include("callback_url")
    end
  end
end
