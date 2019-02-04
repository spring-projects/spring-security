/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.config.crypto;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.ConversionService;
import org.springframework.core.convert.support.GenericConversionService;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestRule;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Tests for {@link RsaKeyConversionServicePostProcessor}
 */
public class RsaKeyConversionServicePostProcessorTests {

	private static final String PKCS8_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\n" +
			"MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCMk7CKSTfu3QoV\n" +
			"HoPVXxwZO+qweztd36cVWYqGOZinrOR2crWFu50AgR2CsdIH0+cqo7F4Vx7/3O8i\n" +
			"RpYYZPe2VoO5sumzJt8P6fS80/TAKjhJDAqgZKRJTgGN8KxCM6p/aJli1ZeDBqiV\n" +
			"v7vJJe+ZgJuPGRS+HMNa/wPxEkqqXsglcJcQV1ZEtfKXSHB7jizKpRL38185SyAC\n" +
			"pwyjvBu6Cmm1URfhQo88mf239ONh4dZ2HoDfzN1q6Ssu4F4hgutxr9B0DVLDP5u+\n" +
			"WFrm3nsJ76zf99uJ+ntMUHJ+bY+gOjSlVWIVBIZeAaEGKCNWRk/knjvjbijpvm3U\n" +
			"acGlgdL3AgMBAAECggEACxxxS7zVyu91qI2s5eSKmAQAXMqgup6+2hUluc47nqUv\n" +
			"uZz/c/6MPkn2Ryo+65d4IgqmMFjSfm68B/2ER5FTcvoLl1Xo2twrrVpUmcg3BClS\n" +
			"IZPuExdhVNnxjYKEWwcyZrehyAoR261fDdcFxLRW588efIUC+rPTTRHzAc7sT+Ln\n" +
			"t/uFeYNWJm3LaegOLoOmlMAhJ5puAWSN1F0FxtRf/RVgzbLA9QC975SKHJsfWCSr\n" +
			"IZyPsdeaqomKaF65l8nfqlE0Ua2L35gIOGKjUwb7uUE8nI362RWMtYdoi3zDDyoY\n" +
			"hSFbgjylCHDM0u6iSh6KfqOHtkYyJ8tUYgVWl787wQKBgQDYO3wL7xuDdD101Lyl\n" +
			"AnaDdFB9fxp83FG1cWr+t7LYm9YxGfEUsKHAJXN6TIayDkOOoVwIl+Gz0T3Z06Bm\n" +
			"eBGLrB9mrVA7+C7NJwu5gTMlzP6HxUR9zKJIQ/VB1NUGM77LSmvOFbHc9Q0+z8EH\n" +
			"X5WO516a3Z7lNtZJcCoPOtu2rwKBgQCmbj41Fh+SSEUApCEKms5ETRpe7LXQlJgx\n" +
			"yW7zcJNNuIb1C3vBLPxjiOTMgYKOeMg5rtHTGLT43URHLh9ArjawasjSAr4AM3J4\n" +
			"xpoi/sKGDdiKOsuDWIGfzdYL8qyTHSdpZLQsCTMRiRYgAHZFPgNa7SLZRfZicGlr\n" +
			"GHN1rJW6OQKBgEjiM/upyrJSWeypUDSmUeAZMpA6aWkwsfHgmtnkfUn5rQa74cDB\n" +
			"kKO9e+D7LmOR3z+SL/1NhGwh2SE07dncGr3jdGodfO/ZxZyszozmeaECKcEFwwJM\n" +
			"GV8WWPKplGwUwPiwywmZ0mvRxXcoe73KgBS88+xrSwWjqDL0tZiQlEJNAoGATkei\n" +
			"GMQMG3jEg9Wu+NbxV6zQT3+U0MNjhl9RQU1c63x0dcNt9OFc4NAdlZcAulRTENaK\n" +
			"OHjxffBM0hH+fySx8m53gFfr2BpaqDX5f6ZGBlly1SlsWZ4CchCVsc71nshipi7I\n" +
			"k8HL9F5/OpQdDNprJ5RMBNfkWE65Nrcsb1e6oPkCgYAxwgdiSOtNg8PjDVDmAhwT\n" +
			"Mxj0Dtwi2fAqQ76RVrrXpNp3uCOIAu4CfruIb5llcJ3uak0ZbnWri32AxSgk80y3\n" +
			"EWiRX/WEDu5znejF+5O3pI02atWWcnxifEKGGlxwkcMbQdA67MlrJLFaSnnGpNXo\n" +
			"yPfcul058SOqhafIZQMEKQ==\n" +
			"-----END PRIVATE KEY-----";
	private static final String X509_PUBLIC_KEY_LOCATION =
			"classpath:org/springframework/security/config/annotation/web/configuration/simple.pub";

	private final RsaKeyConversionServicePostProcessor postProcessor =
			new RsaKeyConversionServicePostProcessor();
	private ConversionService service;

	@Value("classpath:org/springframework/security/config/annotation/web/configuration/simple.pub")
	RSAPublicKey publicKey;

	@Value("classpath:org/springframework/security/config/annotation/web/configuration/simple.priv")
	RSAPrivateKey privateKey;

	@Value("custom:simple.pub")
	RSAPublicKey samePublicKey;

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Before
	public void setUp() {
		ConfigurableListableBeanFactory beanFactory = new DefaultListableBeanFactory();
		beanFactory.setConversionService(new GenericConversionService());
		this.postProcessor.postProcessBeanFactory(beanFactory);
		this.service = beanFactory.getConversionService();
	}

	@Test
	public void convertWhenUsingConversionServiceForRawKeyThenOk() {
		RSAPrivateKey key = this.service.convert(PKCS8_PRIVATE_KEY, RSAPrivateKey.class);
		assertThat(key.getModulus().bitLength()).isEqualTo(2048);
	}

	@Test
	public void convertWhenUsingConversionServiceForClasspathThenOk() {
		RSAPublicKey key = this.service.convert(X509_PUBLIC_KEY_LOCATION, RSAPublicKey.class);
		assertThat(key.getModulus().bitLength()).isEqualTo(1024);
	}

	@Test
	public void valueWhenReferringToClasspathPublicKeyThenConverts() {
		this.spring.register(CustomResourceLoaderConfig.class, DefaultConfig.class).autowire();
		assertThat(this.publicKey.getModulus().bitLength()).isEqualTo(1024);
	}

	@Test
	public void valueWhenReferringToClasspathPrivateKeyThenConverts() {
		this.spring.register(CustomResourceLoaderConfig.class, DefaultConfig.class).autowire();
		assertThat(this.privateKey.getModulus().bitLength()).isEqualTo(2048);
	}

	@Test
	public void valueWhenReferringToCustomResourceLoadedPublicKeyThenConverts() {
		this.spring.register(CustomResourceLoaderConfig.class, DefaultConfig.class).autowire();
		assertThat(this.samePublicKey.getModulus().bitLength()).isEqualTo(1024);
	}

	@Test
	public void valueWhenOverridingConversionServiceThenUsed() {
		assertThatCode(() ->
				this.spring.register(OverrideConversionServiceConfig.class, DefaultConfig.class).autowire())
				.hasRootCauseInstanceOf(IllegalArgumentException.class);
	}

	@EnableWebSecurity
	static class DefaultConfig { }

	@Configuration
	static class CustomResourceLoaderConfig {
		@Bean
		BeanFactoryPostProcessor conversionServiceCustomizer() {
			return beanFactory -> beanFactory.getBean(RsaKeyConversionServicePostProcessor.class)
					.setResourceLoader(new CustomResourceLoader());
		}
	}

	@Configuration
	static class OverrideConversionServiceConfig {
		@Bean
		ConversionService conversionService() {
			GenericConversionService service = new GenericConversionService();
			service.addConverter(String.class, RSAPublicKey.class, source -> {
				throw new IllegalArgumentException("unsupported");
			});
			return service;
		}
	}

	private static class CustomResourceLoader implements ResourceLoader {
		private final ResourceLoader delegate = new DefaultResourceLoader();

		@Override
		public Resource getResource(String location) {
			if (location.startsWith("classpath:")) {
				return this.delegate.getResource(location);
			} else if (location.startsWith("custom:")) {
				String[] parts = location.split(":");
				return this.delegate.getResource(
						"classpath:org/springframework/security/config/annotation/web/configuration/" + parts[1]);
			}
			throw new IllegalArgumentException("unsupported resource");
		}

		@Override
		public ClassLoader getClassLoader() {
			return this.delegate.getClassLoader();
		}
	}
}
