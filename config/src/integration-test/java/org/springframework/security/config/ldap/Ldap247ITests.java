package org.springframework.security.config.ldap;

import javax.naming.Name;

import org.junit.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.ldap.core.support.BaseLdapPathAware;
import org.springframework.ldap.core.support.BaseLdapPathBeanPostProcessor;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.server.UnboundIdContainer;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(SpringTestContextExtension.class)
public class Ldap247ITests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	private LdapGroupDao ldapGroupDao;

	@Test
	public void verifyThatBasePathIsProperlyPopulated() {
		this.spring.register(FromContextSourceConfig.class).autowire();
		assertThat(this.ldapGroupDao).isNotNull();
		assertThat(this.ldapGroupDao.getBasePath()).isNotNull();
	}

	@Configuration
	@EnableMethodSecurity
	@Import(BaseLdapServerConfig.class)
	static class FromContextSourceConfig {

		@Bean
		AuthenticationManager authenticationManager(BaseLdapPathContextSource contextSource) {
			LdapBindAuthenticationManagerFactory factory = new LdapBindAuthenticationManagerFactory(contextSource);
			factory.setUserDnPatterns("uid={0},ou=people");
			return factory.createAuthenticationManager();
		}

		@Bean
		static MethodSecurityExpressionHandler securityExpressionHandler(LdapGroupDao ldap) {
			return new MethodSecurityExpressionHandler(ldap);
		}

		@Bean
		static LdapGroupDao ldapGroupDao() {
			return new LdapGroupDao();
		}

		@Bean
		static BaseLdapPathBeanPostProcessor baseLdapPathBeanPostProcessor() {
			return new BaseLdapPathBeanPostProcessor();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class BaseLdapServerConfig implements DisposableBean {

		private UnboundIdContainer container;

		@Bean
		UnboundIdContainer ldapServer() {
			this.container = new UnboundIdContainer("dc=springframework,dc=org", "classpath:/test-server.ldif");
			this.container.setPort(0);
			return this.container;
		}

		@Bean
		BaseLdapPathContextSource contextSource(UnboundIdContainer container) {
			int port = container.getPort();
			return new DefaultSpringSecurityContextSource("ldap://localhost:" + port + "/dc=springframework,dc=org");
		}

		@Override
		public void destroy() {
			this.container.stop();
		}

	}

	static class MethodSecurityExpressionHandler extends DefaultMethodSecurityExpressionHandler {

		private final LdapGroupDao groupDao;

		MethodSecurityExpressionHandler(LdapGroupDao groupDao) {
			this.groupDao = groupDao;
		}

	}

	static class LdapGroupDao implements BaseLdapPathAware {

		private Name basePath;

		LdapGroupDao() {
			super();
		}

		@Override
		public void setBaseLdapPath(DistinguishedName baseLdapPath) {
			this.basePath = baseLdapPath;
		}

		public Name getBasePath() {
			return this.basePath;
		}
	}

}
