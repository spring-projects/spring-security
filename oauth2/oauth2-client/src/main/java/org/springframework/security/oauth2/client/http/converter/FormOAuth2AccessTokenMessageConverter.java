package org.springframework.security.oauth2.client.http.converter;

import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.AbstractHttpMessageConverter;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.security.oauth2.client.util.OAuth2Utils;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.util.MultiValueMap;

import java.io.IOException;
import java.util.*;

/**
 * Created by XYUU on 2018/4/23.
 */
public class FormOAuth2AccessTokenMessageConverter extends AbstractHttpMessageConverter<OAuth2AccessTokenResponse> {

    private final FormHttpMessageConverter delegateMessageConverter;

    public FormOAuth2AccessTokenMessageConverter(FormHttpMessageConverter delegateMessageConverter) {
        super(MediaType.APPLICATION_FORM_URLENCODED, MediaType.TEXT_PLAIN, MediaType.TEXT_HTML);
        this.delegateMessageConverter = delegateMessageConverter;
    }

    @Override
    protected boolean supports(Class<?> clazz) {
        return OAuth2AccessTokenResponse.class.equals(clazz);
    }

    @Override
    protected OAuth2AccessTokenResponse readInternal(Class<? extends OAuth2AccessTokenResponse> clazz, HttpInputMessage inputMessage)
            throws IOException, HttpMessageNotReadableException {
        MultiValueMap<String, String> data = delegateMessageConverter.read(null, inputMessage);
        String tokenValue = null;
        String tokenType = null;
        String refreshToken = null;
        Long expiresIn = 0L;
        Set<String> scope = null;
        Map<String, Object> additionalInformation = new LinkedHashMap<String, Object>();
        for (Map.Entry<String, List<String>> entry : data.entrySet()) {
            String name = entry.getKey();
            List<String> values = entry.getValue();
            switch (name) {
                case "access_token":
                    tokenValue = values.get(0);
                    break;
                case "token_type":
                    tokenType = values.get(0);
                    break;
                case "refresh_token":
                    refreshToken = values.get(0);
                    break;
                case "expires_in":
                    expiresIn = Long.valueOf(values.get(0));
                    break;
                case "scope":
                    scope = parseScope(values);
                    break;
                default:
                    additionalInformation.put(name, values.get(0));
            }
        }
        return OAuth2AccessTokenResponse.withToken(tokenValue)
                .tokenType(OAuth2AccessToken.TokenType.BEARER)
                .expiresIn(expiresIn)
                .scopes(scope)
                .additionalParameters(additionalInformation).build();
    }

    private Set<String> parseScope(List<String> values) {
        Set<String> scope;
        if (values.size() > 1) {
            scope = new TreeSet<>();
            scope.addAll(values);
        } else {
            scope = OAuth2Utils.parseParameterList(values.get(0));
        }
        return scope;
    }

    @Override
    protected void writeInternal(OAuth2AccessTokenResponse oAuth2AccessTokenResponse, HttpOutputMessage outputMessage) throws IOException, HttpMessageNotWritableException {
        throw new UnsupportedOperationException("This converter is only used for converting from externally aqcuired form data");
    }

}
