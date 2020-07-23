package org.springframework.security.config.annotation.authentication.builders;

import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.InMemoryUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.JdbcUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.authentication.configurers.userdetails.DaoAuthenticationConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * A {@code AuthenticationManagerBuilder} implementation that uses defaultPasswordEncoder
 *
 * @author Rob Winch
 * @author He Bo
 */
public class DefaultPasswordEncoderAuthenticationManagerBuilder extends AuthenticationManagerBuilder {

	private PasswordEncoder defaultPasswordEncoder;

	/**
	 * Creates a new instance
	 *
	 * @param objectPostProcessor the {@link ObjectPostProcessor} instance to use.
	 */
	public DefaultPasswordEncoderAuthenticationManagerBuilder(
			ObjectPostProcessor<Object> objectPostProcessor, PasswordEncoder defaultPasswordEncoder) {
		super(objectPostProcessor);
		this.defaultPasswordEncoder = defaultPasswordEncoder;
	}

	@Override
	public InMemoryUserDetailsManagerConfigurer<AuthenticationManagerBuilder> inMemoryAuthentication()
			throws Exception {
		return super.inMemoryAuthentication()
				.passwordEncoder(this.defaultPasswordEncoder);
	}

	@Override
	public JdbcUserDetailsManagerConfigurer<AuthenticationManagerBuilder> jdbcAuthentication()
			throws Exception {
		return super.jdbcAuthentication()
				.passwordEncoder(this.defaultPasswordEncoder);
	}

	@Override
	public <T extends UserDetailsService> DaoAuthenticationConfigurer<AuthenticationManagerBuilder, T> userDetailsService(
			T userDetailsService) throws Exception {
		return super.userDetailsService(userDetailsService)
				.passwordEncoder(this.defaultPasswordEncoder);
	}

}
