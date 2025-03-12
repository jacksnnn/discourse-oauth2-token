# frozen_string_literal: true

class OmniAuth::Strategies::Oauth2Basic < ::OmniAuth::Strategies::OAuth2
  option :name, "oauth2_basic"

  uid do
    Rails.logger.warn("OAUTH2 DEBUG: Executing uid method in Oauth2Basic strategy")
    if path = SiteSetting.oauth2_callback_user_id_path.split(".")
      Rails.logger.warn("OAUTH2 DEBUG: Using path from oauth2_callback_user_id_path: #{path.join('.')}")
      result = recurse(access_token, [*path]) if path.present?
      Rails.logger.warn("OAUTH2 DEBUG: UID result: #{result}")
      result
    end
  end

  info do
    Rails.logger.warn("OAUTH2 DEBUG: Executing info method in Oauth2Basic strategy")
    if paths = SiteSetting.oauth2_callback_user_info_paths.split("|")
      result = Hash.new
      paths.each do |p|
        segments = p.split(":")
        if segments.length == 2
          key = segments.first
          path = [*segments.last.split(".")]
          value = recurse(access_token, path)
          Rails.logger.warn("OAUTH2 DEBUG: Info path '#{p}' => '#{value}'")
          result[key] = value
        end
      end
      Rails.logger.warn("OAUTH2 DEBUG: Info result: #{result}")
      result
    end
  end

  def callback_url
    url = Discourse.base_url_no_prefix + script_name + callback_path
    Rails.logger.warn("OAUTH2 DEBUG: Callback URL is: #{url}")
    url
  end

  def recurse(obj, keys)
    Rails.logger.warn("OAUTH2 DEBUG: Recursing with keys: #{keys.join('.')} on object type: #{obj.class.name}")
    return nil if !obj
    k = keys.shift
    result = obj.respond_to?(k) ? obj.send(k) : obj[k]
    keys.empty? ? result : recurse(result, keys)
  end
end
