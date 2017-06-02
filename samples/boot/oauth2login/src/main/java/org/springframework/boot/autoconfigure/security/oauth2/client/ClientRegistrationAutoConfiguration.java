/*
 * Copyright 2012-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.boot.autoconfigure.security.oauth2.client;

import org.springframework.beans.factory.config.YamlPropertiesFactoryBean;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.*;
import org.springframework.boot.autoconfigure.security.SecurityAutoConfiguration;
import org.springframework.boot.context.properties.bind.BindResult;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.*;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.Environment;
import org.springframework.core.env.MutablePropertySources;
import org.springframework.core.env.PropertiesPropertySource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationProperties;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.util.CollectionUtils;

import java.util.*;
import java.util.stream.Collectors;

/**
 * @author Joe Grandja
 */
@Configuration
@ConditionalOnWebApplication
@ConditionalOnClass(ClientRegistrationRepository.class)
@ConditionalOnMissingBean(ClientRegistrationRepository.class)
@AutoConfigureBefore(SecurityAutoConfiguration.class)
public class ClientRegistrationAutoConfiguration {
	private static final String CLIENTS_DEFAULTS_RESOURCE = "META-INF/oauth2-clients-defaults.yml";
	static final String CLIENT_ID_PROPERTY = "client-id";
	static final String CLIENT_PROPERTY_PREFIX = "security.oauth2.client";

	@Configuration
	@Conditional(ClientPropertiesAvailableCondition.class)
	protected static class ClientRegistrationConfiguration {
		private final Environment environment;

		protected ClientRegistrationConfiguration(Environment environment) {
			this.environment = environment;
		}

		@Bean
		public ClientRegistrationRepository clientRegistrationRepository() {
			MutablePropertySources propertySources = ((ConfigurableEnvironment) this.environment).getPropertySources();
			Properties clientsDefaultProperties = this.getClientsDefaultProperties();
			if (clientsDefaultProperties != null) {
				propertySources.addLast(new PropertiesPropertySource("oauth2ClientsDefaults", clientsDefaultProperties));
			}
			Binder binder = Binder.get(this.environment);
			List<ClientRegistration> clientRegistrations = new ArrayList<>();
			Set<String> clientPropertyKeys = resolveClientPropertyKeys(this.environment);
			for (String clientPropertyKey : clientPropertyKeys) {
				String fullClientPropertyKey = CLIENT_PROPERTY_PREFIX + "." + clientPropertyKey;
				if (!this.environment.containsProperty(fullClientPropertyKey + "." + CLIENT_ID_PROPERTY)) {
					continue;
				}
				ClientRegistrationProperties clientRegistrationProperties = binder.bind(
					fullClientPropertyKey, Bindable.of(ClientRegistrationProperties.class)).get();
				ClientRegistration clientRegistration = new ClientRegistration.Builder(clientRegistrationProperties).build();
				clientRegistrations.add(clientRegistration);
			}

			return new InMemoryClientRegistrationRepository(clientRegistrations);
		}

		private Properties getClientsDefaultProperties() {
			ClassPathResource clientsDefaultsResource = new ClassPathResource(CLIENTS_DEFAULTS_RESOURCE);
			if (!clientsDefaultsResource.exists()) {
				return null;
			}
			YamlPropertiesFactoryBean yamlPropertiesFactory = new YamlPropertiesFactoryBean();
			yamlPropertiesFactory.setResources(clientsDefaultsResource);
			return yamlPropertiesFactory.getObject();
		}
	}

	static Set<String> resolveClientPropertyKeys(Environment environment) {
		Binder binder = Binder.get(environment);
		BindResult<Map<String, Object>> result = binder.bind(
			CLIENT_PROPERTY_PREFIX, Bindable.mapOf(String.class, Object.class));
		return result.get().keySet();
	}

	private static class ClientPropertiesAvailableCondition extends SpringBootCondition implements ConfigurationCondition {

		@Override
		public ConfigurationCondition.ConfigurationPhase getConfigurationPhase() {
			return ConfigurationPhase.PARSE_CONFIGURATION;
		}

		@Override
		public ConditionOutcome getMatchOutcome(ConditionContext context, AnnotatedTypeMetadata metadata) {
			ConditionMessage.Builder message = ConditionMessage.forCondition("OAuth2 Client Properties");
			Set<String> clientPropertyKeys = resolveClientPropertyKeys(context.getEnvironment());
			if (!CollectionUtils.isEmpty(clientPropertyKeys)) {
				return ConditionOutcome.match(message.foundExactly("OAuth2 Client(s) -> " +
					clientPropertyKeys.stream().collect(Collectors.joining(", "))));
			}
			return ConditionOutcome.noMatch(message.notAvailable("OAuth2 Client(s)"));
		}
	}
}
