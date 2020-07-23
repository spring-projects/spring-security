package org.springframework.security.config.crypto.password;

import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * A {@code PasswordEncoder} implementation that uses passwordEncoder like follow:
 * <ul>
 *  <li>1. Find from the {@link #applicationContext}.</li>
 *  <li>2. Create by {@link PasswordEncoderFactories#createDelegatingPasswordEncoder()}.</li>
 * <ul/>
 *
 * @author Rob Winch
 * @author He Bo
 */
public class LazyPasswordEncoder implements PasswordEncoder {
	private ApplicationContext applicationContext;
	private volatile PasswordEncoder passwordEncoder;

	private final Object monitor = new Object();

	public LazyPasswordEncoder(ApplicationContext applicationContext) {
		this.applicationContext = applicationContext;
	}

	@Override
	public String encode(CharSequence rawPassword) {
		return getPasswordEncoder().encode(rawPassword);
	}

	@Override
	public boolean matches(CharSequence rawPassword,
						   String encodedPassword) {
		return getPasswordEncoder().matches(rawPassword, encodedPassword);
	}

	@Override
	public boolean upgradeEncoding(String encodedPassword) {
		return getPasswordEncoder().upgradeEncoding(encodedPassword);
	}

	private PasswordEncoder getPasswordEncoder() {
		if (this.passwordEncoder != null) {
			return this.passwordEncoder;
		}

		synchronized (monitor) {
			if(this.passwordEncoder != null) {
				return passwordEncoder;
			}
			this.passwordEncoder = getBeanOrNull(PasswordEncoder.class);
			if (this.passwordEncoder == null) {
				this.passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
			}
		}
		return this.passwordEncoder;
	}

	private <T> T getBeanOrNull(Class<T> type) {
		try {
			return this.applicationContext.getBean(type);
		} catch (NoSuchBeanDefinitionException notFound) {
			return null;
		}
	}

	@Override
	public String toString() {
		return getPasswordEncoder().toString();
	}
}
