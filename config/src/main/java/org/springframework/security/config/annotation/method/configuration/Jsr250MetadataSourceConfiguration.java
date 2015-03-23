package org.springframework.security.config.annotation.method.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.annotation.Jsr250MethodSecurityMetadataSource;

@Configuration
class Jsr250MetadataSourceConfiguration {

	@Bean
	public Jsr250MethodSecurityMetadataSource jsr250MethodSecurityMetadataSource() {
		return new Jsr250MethodSecurityMetadataSource();
	}
}
