package sample;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.context.annotation.Configuration;

import java.util.HashSet;
import java.util.Set;

@Configuration
@ConfigurationProperties("spring.security.oauth2.resourceserver")
public class OAuth2ResourceServerConfig {

	@NestedConfigurationProperty
	private JwtConfig jwt;

	@NestedConfigurationProperty
	private Set<JwtConfig> multiTenantJwt = new HashSet<>();

	@NestedConfigurationProperty
	private OpaqueConfig opaque;

	public JwtConfig getJwt() {
		return jwt;
	}

	public void setJwt(JwtConfig jwt) {
		this.jwt = jwt;
	}

	public Set<JwtConfig> getMultiTenantJwt() {
		return multiTenantJwt;
	}

	public OpaqueConfig getOpaque() {
		return opaque;
	}

	public void setOpaque(OpaqueConfig opaque) {
		this.opaque = opaque;
	}

	public static class JwtConfig {
		private String issuerUri;
		private String jwkSetUri;

		public String getIssuerUri() {
			return issuerUri;
		}

		public void setIssuerUri(String issuerUri) {
			this.issuerUri = issuerUri;
		}

		public String getJwkSetUri() {
			return jwkSetUri;
		}

		public void setJwkSetUri(String jwkSetUri) {
			this.jwkSetUri = jwkSetUri;
		}
	}

	public static class OpaqueConfig {

		private String introspectionUri;

		public String getIntrospectionUri() {
			return introspectionUri;
		}

		public void setIntrospectionUri(String introspectionUri) {
			this.introspectionUri = introspectionUri;
		}

	}
}
