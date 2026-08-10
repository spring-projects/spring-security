package org.springframework.security.docs.servlet.authentication.mfawhenwebauthnregistered;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authorization.EnableMultiFactorAuthentication;
import org.springframework.security.config.annotation.authorization.MultiFactorCondition;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.web.webauthn.management.MapPublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.MapUserCredentialRepository;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
// tag::enable-mfa-webauthn[]
@EnableMultiFactorAuthentication(
	authorities = {
		FactorGrantedAuthority.PASSWORD_AUTHORITY,
		FactorGrantedAuthority.WEBAUTHN_AUTHORITY
	},
	when = MultiFactorCondition.WEBAUTHN_REGISTERED
)
public class WebAuthnConditionConfiguration {

	@Bean
	public PublicKeyCredentialUserEntityRepository userEntityRepository() {
		return new MapPublicKeyCredentialUserEntityRepository();
	}

	@Bean
	public UserCredentialRepository userCredentialRepository() {
		return new MapUserCredentialRepository();
	}

}
// end::enable-mfa-webauthn[]
