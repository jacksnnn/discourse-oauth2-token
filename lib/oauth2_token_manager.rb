# frozen_string_literal: true

class OAuth2TokenManager
  def self.refresh_token(user)
    refresh_token = user.custom_fields["oauth2_refresh_token"]
    Rails.logger.warn("OAUTH2 DEBUG: refresh_token called for user #{user.username} (id: #{user.id})")
    Rails.logger.warn("OAUTH2 DEBUG: refresh_token value present: #{refresh_token.present?}")
    
    return false if refresh_token.blank?
    
    # Create OAuth2 client
    client = create_oauth2_client
    Rails.logger.warn("OAUTH2 DEBUG: Created OAuth2 client with token URL: #{SiteSetting.oauth2_token_url}")
    
    begin
      # Create access token object with the refresh token
      access_token = OAuth2::AccessToken.new(
        client,
        user.custom_fields["current_access_token"],
        refresh_token: refresh_token
      )
      
      Rails.logger.warn("OAUTH2 DEBUG: Created AccessToken object, attempting to refresh...")
      
      # Refresh the token
      refreshed_token = access_token.refresh!
      Rails.logger.warn("OAUTH2 DEBUG: Token successfully refreshed")
      
      # Update user's custom fields with the new tokens
      user.custom_fields["current_access_token"] = refreshed_token.token
      Rails.logger.warn("OAUTH2 DEBUG: Updated current_access_token")
      
      # Update refresh token if a new one was provided
      if refreshed_token.refresh_token.present?
        user.custom_fields["oauth2_refresh_token"] = refreshed_token.refresh_token
        Rails.logger.warn("OAUTH2 DEBUG: Updated refresh_token")
      end
      
      # Update expiry time
      if refreshed_token.expires_at.present?
        user.custom_fields["oauth2_token_expires_at"] = refreshed_token.expires_at
        Rails.logger.warn("OAUTH2 DEBUG: Updated token_expires_at with expires_at: #{refreshed_token.expires_at}")
      elsif refreshed_token.expires_in.present?
        user.custom_fields["oauth2_token_expires_at"] = Time.now.to_i + refreshed_token.expires_in
        Rails.logger.warn("OAUTH2 DEBUG: Updated token_expires_at with expires_in: current time + #{refreshed_token.expires_in}")
      end
      
      user.save_custom_fields(true)
      
      Rails.logger.info("Successfully refreshed OAuth2 token for user #{user.id}")
      true
    rescue => e
      Rails.logger.error("OAUTH2 ERROR: Error refreshing OAuth2 token for user #{user.id}: #{e.message}")
      Rails.logger.error("OAUTH2 ERROR: Backtrace: #{e.backtrace.join("\n")}")
      false
    end
  end
  
  def self.create_oauth2_client
    client_config = {
      site: SiteSetting.oauth2_authorize_url.split('/').first(3).join('/'),
      token_url: SiteSetting.oauth2_token_url,
      authorize_url: SiteSetting.oauth2_authorize_url,
      token_method: SiteSetting.oauth2_token_url_method.downcase.to_sym
    }
    
    Rails.logger.warn("OAUTH2 DEBUG: Creating OAuth2 client with config: #{client_config}")
    
    OAuth2::Client.new(
      SiteSetting.oauth2_client_id,
      SiteSetting.oauth2_client_secret,
      client_config
    )
  end
  
  def self.token_expired?(user)
    expires_at = user.custom_fields["oauth2_token_expires_at"].to_i
    Rails.logger.warn("OAUTH2 DEBUG: Checking token expiry for user #{user.username}, expires_at: #{expires_at}")
    
    return true if expires_at.zero?
    
    # Consider the token expired if it expires in less than 30 minutes
    is_expired = expires_at < Time.now.to_i + 30.minutes.to_i
    Rails.logger.warn("OAUTH2 DEBUG: Token expired? #{is_expired} (now + 30min: #{Time.now.to_i + 30.minutes.to_i})")
    
    is_expired
  end
  
  def self.get_token(user)
    Rails.logger.warn("OAUTH2 DEBUG: get_token called for user #{user.username}")
    
    # Check if token is expired and refresh if needed
    if token_expired?(user) && user.custom_fields["oauth2_refresh_token"].present?
      Rails.logger.warn("OAUTH2 DEBUG: Token is expired, attempting refresh")
      refresh_success = refresh_token(user)
      Rails.logger.warn("OAUTH2 DEBUG: Token refresh result: #{refresh_success ? 'success' : 'failed'}")
    else
      Rails.logger.warn("OAUTH2 DEBUG: Token is still valid or no refresh token available")
    end
    
    token = user.custom_fields["current_access_token"]
    Rails.logger.warn("OAUTH2 DEBUG: Returning token (present: #{token.present?})")
    
    token
  end
end 