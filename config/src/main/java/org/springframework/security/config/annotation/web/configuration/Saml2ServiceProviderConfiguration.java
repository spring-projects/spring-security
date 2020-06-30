/*
 * Copyright 2002-2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.config.annotation.web.configuration;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import javax.xml.XMLConstants;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.ParserPool;
import org.joda.time.DateTime;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.ImportSelector;
import org.springframework.core.Ordered;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.util.ClassUtils;

import static java.lang.Boolean.FALSE;
import static java.lang.Boolean.TRUE;
import static org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport.getBuilderFactory;
import static org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport.setParserPool;

/**
 * {@link Configuration} for SAML 2.0 Service Provider support
 *
 * <p>
 * This {@code Configuration} is conditionally imported by {@link Saml2ImportSelector}
 * when the {@code spring-security-saml2-service-provider} module is present on the classpath.
 *
 * @author Josh Cummings
 * @since 5.4
 * @see Saml2ImportSelector
 */
@Import(Saml2ServiceProviderConfiguration.OpenSamlImportSelector.class)
final class Saml2ServiceProviderConfiguration {

	static class OpenSamlImportSelector implements ImportSelector {

		@Override
		public String[] selectImports(AnnotationMetadata importingClassMetadata) {
			boolean opensamlPresent = ClassUtils.isPresent(
					"org.opensaml.core.config.InitializationService", getClass().getClassLoader());

			return opensamlPresent ?
					new String[] { "org.springframework.security.config.annotation.web.configuration.Saml2ServiceProviderConfiguration.OpenSamlServiceProviderConfiguration" } :
					new String[0];
		}
	}

	@Configuration(proxyBeanMethods = false)
	static class OpenSamlServiceProviderConfiguration {
		@Bean
		BeanFactoryPostProcessor saml2BeanFactoryPostProcessor() {
			return new OpenSamlServiceProviderBeanFactoryPostProcessor();
		}

		private static class OpenSamlServiceProviderBeanFactoryPostProcessor
				implements BeanFactoryPostProcessor, Ordered {

			@Override
			public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
				if (ConfigurationService.get(XMLObjectProviderRegistry.class) == null) {
					try {
						InitializationService.initialize();
					} catch (InitializationException e) {
						throw new Saml2Exception("Unable to initialize OpenSAML", e);
					}

					ParserPool parserPool = initializeParserPool();
					setParserPool(parserPool);

					XMLObjectBuilderFactory builderFactory = getBuilderFactory();
					builderFactory.registerBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME, new DefaultAuthnRequestBuilder());
				}
			}

			@Override
			public int getOrder() {
				return Ordered.LOWEST_PRECEDENCE;
			}

			private ParserPool initializeParserPool() {
				BasicParserPool parserPool = new BasicParserPool();

				parserPool.setMaxPoolSize(50);
				Map<String, Boolean> parserBuilderFeatures = new HashMap<>();
				parserBuilderFeatures.put("http://apache.org/xml/features/disallow-doctype-decl", TRUE);
				parserBuilderFeatures.put(XMLConstants.FEATURE_SECURE_PROCESSING, TRUE);
				parserBuilderFeatures.put("http://xml.org/sax/features/external-general-entities", FALSE);
				parserBuilderFeatures.put("http://apache.org/xml/features/validation/schema/normalized-value", FALSE);
				parserBuilderFeatures.put("http://xml.org/sax/features/external-parameter-entities", FALSE);
				parserBuilderFeatures.put("http://apache.org/xml/features/dom/defer-node-expansion", FALSE);
				parserPool.setBuilderFeatures(parserBuilderFeatures);

				try {
					parserPool.initialize();
				}
				catch (ComponentInitializationException x) {
					throw new Saml2Exception("Unable to initialize OpenSAML ParserPool", x);
				}

				return parserPool;
			}
		}

		private static class DefaultAuthnRequestBuilder extends AuthnRequestBuilder {
			@Override
			public AuthnRequest buildObject() {
				AuthnRequest authnRequest = super.buildObject();
				authnRequest.setID("ARQ" + UUID.randomUUID().toString().substring(1));
				authnRequest.setIssueInstant(new DateTime());
				authnRequest.setForceAuthn(Boolean.FALSE);
				authnRequest.setIsPassive(Boolean.FALSE);
				authnRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
				return authnRequest;
			}
		}
	}


}
