/*
 * Copyright 2002-2017 the original author or authors.
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

package sample;

import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.config.ViewResolverRegistry;
import org.springframework.web.reactive.config.WebFluxConfigurer;
import org.thymeleaf.spring5.ISpringWebFluxTemplateEngine;
import org.thymeleaf.spring5.SpringWebFluxTemplateEngine;
import org.thymeleaf.spring5.templateresolver.SpringResourceTemplateResolver;
import org.thymeleaf.spring5.view.reactive.ThymeleafReactiveViewResolver;
import org.thymeleaf.templatemode.TemplateMode;

/**
 * @author Rob Winch
 * @since 5.0
 */
@Configuration
public class ThymeleafConfig implements WebFluxConfigurer {
	private ApplicationContext applicationContext;

	public ThymeleafConfig(final ApplicationContext applicationContext) {
		this.applicationContext = applicationContext;
	}

	@Bean
	public SpringResourceTemplateResolver thymeleafTemplateResolver() {

		SpringResourceTemplateResolver resolver = new SpringResourceTemplateResolver();
		resolver.setApplicationContext(this.applicationContext);
		resolver.setPrefix("classpath:/templates/");
		resolver.setSuffix(".html");
		resolver.setTemplateMode(TemplateMode.HTML);
		resolver.setCacheable(false);
		resolver.setCheckExistence(true);
		return resolver;

	}

	@Bean
	public ISpringWebFluxTemplateEngine thymeleafTemplateEngine() {
		SpringWebFluxTemplateEngine templateEngine = new SpringWebFluxTemplateEngine();
		templateEngine.setTemplateResolver(thymeleafTemplateResolver());
		return templateEngine;
	}

	@Bean
	public ThymeleafReactiveViewResolver thymeleafChunkedAndDataDrivenViewResolver() {
		ThymeleafReactiveViewResolver viewResolver = new ThymeleafReactiveViewResolver();
		viewResolver.setTemplateEngine(thymeleafTemplateEngine());
		viewResolver.setOrder(1);
		viewResolver.setResponseMaxChunkSizeBytes(8192); // OUTPUT BUFFER size limit
		return viewResolver;
	}

	@Override
	public void configureViewResolvers(ViewResolverRegistry registry) {
		registry.viewResolver(thymeleafChunkedAndDataDrivenViewResolver());
	}
}
