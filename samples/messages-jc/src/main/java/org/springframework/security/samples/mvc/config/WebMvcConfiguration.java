package org.springframework.security.samples.mvc.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.core.Ordered;
import org.springframework.data.repository.support.DomainClassConverter;
import org.springframework.format.support.FormattingConversionService;
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
@ComponentScan("org.springframework.security.samples.mvc")
public class WebMvcConfiguration extends WebMvcConfigurerAdapter {

	@Autowired
	private FormattingConversionService mvcConversionService;

	@Override
	public void addViewControllers(ViewControllerRegistry registry) {
		registry.addViewController("/login").setViewName("login");
		registry.setOrder(Ordered.HIGHEST_PRECEDENCE);
	}

	@Override
	public void addResourceHandlers(ResourceHandlerRegistry registry) {
		registry.addResourceHandler("/resources/**")
				.addResourceLocations("classpath:/resources/").setCachePeriod(31556926);
		registry.setOrder(Ordered.HIGHEST_PRECEDENCE);
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
