# frozen_string_literal: true

class OAuth2TokenManager
  def self.refresh_token(user)
    refresh_token = user.custom_fields["oauth2_refresh_token"]
    return false if refresh_token.blank?
    
    # Create OAuth2 client
    client = create_oauth2_client
    
    begin
      # Create access token object with the refresh token
      access_token = OAuth2::AccessToken.new(
        client,
        user.custom_fields["current_access_token"],
        refresh_token: refresh_token
      )
      
      # Refresh the token
      refreshed_token = access_token.refresh!
      
      # Update user's custom fields with the new tokens
      user.custom_fields["current_access_token"] = refreshed_token.token
      
      # Update refresh token if a new one was provided
      if refreshed_token.refresh_token.present?
        user.custom_fields["oauth2_refresh_token"] = refreshed_token.refresh_token
      end
      
      # Update expiry time
      if refreshed_token.expires_at.present?
        user.custom_fields["oauth2_token_expires_at"] = refreshed_token.expires_at
      elsif refreshed_token.expires_in.present?
        user.custom_fields["oauth2_token_expires_at"] = Time.now.to_i + refreshed_token.expires_in
      end
      
      user.save_custom_fields(true)
      
      Rails.logger.info("Successfully refreshed OAuth2 token for user #{user.id}")
      true
    rescue => e
      Rails.logger.error("Error refreshing OAuth2 token for user #{user.id}: #{e.message}")
      false
    end
  end
  
  def self.create_oauth2_client
    OAuth2::Client.new(
      SiteSetting.oauth2_client_id,
      SiteSetting.oauth2_client_secret,
      site: SiteSetting.oauth2_authorize_url.split('/').first(3).join('/'),
      token_url: SiteSetting.oauth2_token_url,
      authorize_url: SiteSetting.oauth2_authorize_url,
      token_method: SiteSetting.oauth2_token_url_method.downcase.to_sym
    )
  end
  
  def self.token_expired?(user)
    expires_at = user.custom_fields["oauth2_token_expires_at"].to_i
    return true if expires_at.zero?
    
    # Consider the token expired if it expires in less than 30 minutes
    expires_at < Time.now.to_i + 30.minutes.to_i
  end
  
  def self.get_token(user)
    # Check if token is expired and refresh if needed
    if token_expired?(user) && user.custom_fields["oauth2_refresh_token"].present?
      refresh_token(user)
    end
    
    user.custom_fields["current_access_token"]
  end
end 