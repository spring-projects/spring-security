/*
 * Copyright 2002-2016 the original author or authors.
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
package sample.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.repository.support.DomainClassConverter;
import org.springframework.format.support.FormattingConversionService;
import org.springframework.web.servlet.config.annotation.DefaultServletHandlerConfigurer;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import org.thymeleaf.extras.tiles2.dialect.TilesDialect;
import org.thymeleaf.extras.tiles2.spring4.web.configurer.ThymeleafTilesConfigurer;
import org.thymeleaf.extras.tiles2.spring4.web.view.ThymeleafTilesView;
import org.thymeleaf.spring4.SpringTemplateEngine;
import org.thymeleaf.spring4.view.ThymeleafViewResolver;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;

@EnableWebMvc
@ComponentScan("sample")
public class WebMvcConfiguration extends WebMvcConfigurerAdapter {

	@Autowired
	private FormattingConversionService mvcConversionService;

	@Override
	public void addViewControllers(ViewControllerRegistry registry) {
		registry.addViewController("/login").setViewName("login");
	}

	@Override
	public void addResourceHandlers(ResourceHandlerRegistry registry) {
		registry.addResourceHandler("/resources/**")
				.addResourceLocations("classpath:/resources/").setCachePeriod(31556926);
	}

	@Override
	public void configureDefaultServletHandling(DefaultServletHandlerConfigurer configurer) {
		configurer.enable();
	}

	@Bean
	public ClassLoaderTemplateResolver templateResolver() {
		ClassLoaderTemplateResolver result = new ClassLoaderTemplateResolver();
		result.setPrefix("views/");
		result.setSuffix(".html");
		result.setTemplateMode("HTML5");
		return result;
	}

	@Bean
	public ThymeleafTilesConfigurer tilesConfigurer() {
		ThymeleafTilesConfigurer tilesConfigurer = new ThymeleafTilesConfigurer();
		tilesConfigurer.setDefinitions(new String[] { "classpath:tiles/tiles-def.xml" });
		return tilesConfigurer;
	}

	@Bean
	public SpringTemplateEngine templateEngine(
			ClassLoaderTemplateResolver templateResolver) {
		SpringTemplateEngine templateEngine = new SpringTemplateEngine();
		templateEngine.setTemplateResolver(templateResolver);
		templateEngine.addDialect(new TilesDialect());
		return templateEngine;
	}

	@Bean
	public ThymeleafViewResolver viewResolver(SpringTemplateEngine templateEngine) {
		ThymeleafViewResolver viewResolver = new ThymeleafViewResolver();
		viewResolver.setTemplateEngine(templateEngine);
		viewResolver.setViewClass(ThymeleafTilesView.class);
		return viewResolver;
	}

	@Bean
	public DomainClassConverter<?> domainClassConverter() {
		return new DomainClassConverter<FormattingConversionService>(mvcConversionService);
	}
}
