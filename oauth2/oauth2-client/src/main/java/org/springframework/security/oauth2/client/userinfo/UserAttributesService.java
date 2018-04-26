package org.springframework.security.oauth2.client.userinfo;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Map;

/**
 * Created by XYUU on 2018/4/25.
 */
public interface UserAttributesService {

	String INVALID_USER_INFO_RESPONSE_ERROR_CODE = "invalid_user_info_response";
	ParameterizedTypeReference<Map<String, Object>> typeReference = new ParameterizedTypeReference<Map<String, Object>>() {
	};

	default Map<String, Object> getUserAttributes(ClientRegistration clientRegistration, OAuth2AccessTokenResponse accessTokenResponse) {
		String userInfoUri = clientRegistration.getProviderDetails().getUserInfoEndpoint().getUri();
		Map<String, Object> parameters = accessTokenResponse.getAdditionalParameters();
		Map<String, Object> userAttributes;
		if (!StringUtils.isEmpty(userInfoUri) && getRestTemplate() != null) {
			String url = UriComponentsBuilder.fromHttpUrl(userInfoUri)
					.queryParam("access_token", accessTokenResponse.getAccessToken().getTokenValue())
					.buildAndExpand(parameters).toString();
			ResponseEntity<Map<String, Object>> resp = getRestTemplate().exchange(url, HttpMethod.GET, null, typeReference);
			if (HttpStatus.OK.equals(resp.getStatusCode())) {
				userAttributes = resp.getBody();
			} else {
				OAuth2Error oauth2Error = new OAuth2Error(
						INVALID_USER_INFO_RESPONSE_ERROR_CODE,
						"An error occurred while sending the UserInfo Request for Client Registration: " +
								clientRegistration.getRegistrationId() +
								" Status Code:" + resp.getStatusCodeValue(),
						null
				);
				throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
			}
		} else {
			userAttributes = parameters;
		}
		return userAttributes;
	}

	RestTemplate getRestTemplate();
}
