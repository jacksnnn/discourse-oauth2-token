module ::OAuth2
  class RefreshController < ::ApplicationController
    requires_plugin "discourse-oauth2-basic"

    before_action :ensure_logged_in

    def refresh
      # Use the token manager to get (or refresh) the token
      console.log(" [Controller] Refreshing token for user:", current_user)
      new_token = OAuth2TokenManager.get_token(current_user)
      console.log(" [Controller] New token:", new_token)
      if new_token.present?
        render json: { access_token: new_token }
        console.log(" [Controller] Token refreshed successfully")
      else
        render json: { error: "Failed to refresh token" }, status: 500
        console.log(" [Controller] Failed to refresh token")
      end
    end
  end
end