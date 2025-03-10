# frozen_string_literal: true

# name: discourse-oauth2-basic
# about: Allows users to login to your forum using a basic OAuth2 provider.
# meta_topic_id: 33879
# version: 0.3
# authors: Robin Ward
# url: https://github.com/discourse/discourse-oauth2-basic

enabled_site_setting :oauth2_enabled

require_relative "lib/omniauth/strategies/oauth2_basic"
require_relative "lib/oauth2_faraday_formatter"
require_relative "lib/oauth2_basic_authenticator"

# You should use this register if you want to add custom paths to traverse the user details JSON.
# We'll store the value in the user associated account's extra attribute hash using the full path as the key.
DiscoursePluginRegistry.define_filtered_register :oauth2_basic_additional_json_paths

# After authentication, we'll use this to confirm that the registered json paths are fulfilled, or display an error.
# This requires SiteSetting.oauth2_fetch_user_details? to be true, and can be used with
# DiscoursePluginRegistry.oauth2_basic_additional_json_paths.
#
# Example usage:
# DiscoursePluginRegistry.register_oauth2_basic_required_json_path({
#   path: "extra:data.is_allowed_user",
#   required_value: true,
#   error_message: I18n.t("auth.user_not_allowed")
# }, self)
DiscoursePluginRegistry.define_filtered_register :oauth2_basic_required_json_paths

auth_provider title_setting: "oauth2_button_title", authenticator: OAuth2BasicAuthenticator.new

require_relative "lib/validators/oauth2_basic/oauth2_fetch_user_details_validator"

after_initialize do
  User.register_custom_field_type("current_access_token", :text)
  User.register_custom_field_type("oauth2_refresh_token", :text)
  User.register_custom_field_type("oauth2_token_expires_at", :integer)
  
  # Add a middleware to handle token refreshes
  require_relative "lib/oauth2_token_manager"
  
  # Add a job to periodically check and refresh tokens
  module ::Jobs
    class RefreshOAuth2Tokens < ::Jobs::Scheduled
      every 1.hour
      
      def execute(args)
        return unless SiteSetting.oauth2_enabled
        
        # Find users with tokens that will expire soon (within the next hour)
        expiry_threshold = Time.now.to_i + 1.hour.to_i
        
        User.where("user_custom_fields.name = 'oauth2_token_expires_at' AND user_custom_fields.value::integer < ?", expiry_threshold)
            .joins(:_custom_fields)
            .find_each do |user|
          
          # Skip if no refresh token
          refresh_token = user.custom_fields["oauth2_refresh_token"]
          next unless refresh_token.present?
          
          # Refresh the token
          begin
            OAuth2TokenManager.refresh_token(user)
          rescue => e
            Rails.logger.error("Failed to refresh OAuth2 token for user #{user.id}: #{e.message}")
          end
        end
      end
    end
  end
end
