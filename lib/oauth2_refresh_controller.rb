# frozen_string_literal: true

# The controller needs to be in the correct namespace for Rails routing
# Using ::OAuth2 module creates controllers under o_auth2/
# But our route is expecting oauth2/refresh#refresh
module ::OAuth2
  class RefreshController < ::ApplicationController
    requires_plugin "discourse-oauth2-basic"

    before_action :ensure_logged_in

    def refresh
      # Use the token manager to get (or refresh) the token
      Rails.logger.warn("OAUTH2 DEBUG: RefreshController#refresh called with params: #{params.inspect}")
      Rails.logger.warn("OAUTH2 DEBUG: Controller class: #{self.class.name}, controller_path: #{controller_path}")
      
      begin
        Rails.logger.info(" [Controller] Refreshing token for user: #{current_user.username}")
        new_token = OAuth2TokenManager.get_token(current_user)
        Rails.logger.info(" [Controller] Token obtained: #{new_token ? 'Yes (token present)' : 'No (token missing)'}")
        
        if new_token.present?
          Rails.logger.info(" [Controller] Token refreshed successfully")
          render json: { access_token: new_token }
        else
          Rails.logger.warn(" [Controller] Failed to refresh token - no token returned")
          render json: { error: "Failed to refresh token" }, status: 500
        end
      rescue => e
        Rails.logger.error("OAUTH2 ERROR: Exception in RefreshController#refresh: #{e.class.name} - #{e.message}")
        Rails.logger.error(e.backtrace.join("\n"))
        render json: { error: "Exception occurred: #{e.message}" }, status: 500
      end
    end
  end
end

# Add an alias in the expected namespace for Rails routing
module ::Oauth2
  RefreshController = ::OAuth2::RefreshController
end