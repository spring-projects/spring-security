/*
 * Copyright 2002-2017 the original author or authors.
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

package thymeleaf;

import org.reactivestreams.Publisher;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.core.ReactiveAdapterRegistry;
import org.springframework.core.convert.ConversionService;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.reactive.HandlerMapping;
import org.springframework.web.reactive.result.view.RequestContext;
import org.springframework.web.server.ServerWebExchange;
import org.thymeleaf.IEngineConfiguration;
import org.thymeleaf.exceptions.TemplateProcessingException;
import org.thymeleaf.spring5.ISpringWebFluxTemplateEngine;
import org.thymeleaf.spring5.context.webflux.IReactiveDataDriverContextVariable;
import org.thymeleaf.spring5.context.webflux.SpringWebFluxExpressionContext;
import org.thymeleaf.spring5.context.webflux.SpringWebFluxThymeleafRequestContext;
import org.thymeleaf.spring5.expression.ThymeleafEvaluationContext;
import org.thymeleaf.spring5.naming.SpringContextVariableNames;
import org.thymeleaf.spring5.view.reactive.ThymeleafReactiveView;
import org.thymeleaf.standard.expression.FragmentExpression;
import org.thymeleaf.standard.expression.IStandardExpressionParser;
import org.thymeleaf.standard.expression.StandardExpressionExecutionContext;
import org.thymeleaf.standard.expression.StandardExpressions;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class PatchThymeleafReactiveView extends ThymeleafReactiveView {
	private static final String WEBFLUX_CONVERSION_SERVICE_NAME = "webFluxConversionService";
	@Override
	protected Mono<Void> renderFragmentInternal(
		Set<String> markupSelectorsToRender, Map<String, Object> renderAttributes,
		MediaType contentType, ServerWebExchange exchange) {
		final String viewTemplateName = getTemplateName();
		final ISpringWebFluxTemplateEngine viewTemplateEngine = getTemplateEngine();

		if (viewTemplateName == null) {
			return Mono.error(new IllegalArgumentException("Property 'templateName' is required"));
		}
		if (getLocale() == null) {
			return Mono.error(new IllegalArgumentException("Property 'locale' is required"));
		}
		if (viewTemplateEngine == null) {
			return Mono.error(new IllegalArgumentException("Property 'thymeleafTemplateEngine' is required"));
		}

		final ServerHttpResponse response = exchange.getResponse();

        /*
         * ----------------------------------------------------------------------------------------------------------
         * GATHERING OF THE MERGED MODEL
         * ----------------------------------------------------------------------------------------------------------
         * - The merged model is the map that will be used for initialising the Thymelef IContext. This context will
         *   contain all the data accessible by the template during its execution.
         * - The base of the merged model is the ModelMap created by the Controller, but there are some additional
         *   things
         * ----------------------------------------------------------------------------------------------------------
         */

		final Map<String, Object> mergedModel = new HashMap<>(30);
		// First of all, set all the static variables into the mergedModel
		final Map<String, Object> templateStaticVariables = getStaticVariables();
		if (templateStaticVariables != null) {
			mergedModel.putAll(templateStaticVariables);
		}
		// Add path variables to merged model (if there are any)
		final Map<String, Object> pathVars =
			(Map<String, Object>) exchange.getAttributes().get(HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE);
		if (pathVars != null) {
			mergedModel.putAll(pathVars);
		}
		// Simply dump all the renderAttributes (model coming from the controller) into the merged model
		if (renderAttributes != null) {
			mergedModel.putAll(renderAttributes);
		}

		final ApplicationContext applicationContext = getApplicationContext();

		// Initialize RequestContext (reactive version) and add it to the model as another attribute,
		// so that it can be retrieved from elsewhere.
		final RequestContext requestContext = createRequestContext(exchange, mergedModel);
		final SpringWebFluxThymeleafRequestContext thymeleafRequestContext =
			new SpringWebFluxThymeleafRequestContext(requestContext, exchange);

		mergedModel.put(SpringContextVariableNames.SPRING_REQUEST_CONTEXT, requestContext);
		// Add the Thymeleaf RequestContext wrapper that we will be using in this dialect (the bare RequestContext
		// stays in the context to for compatibility with other dialects)
		mergedModel.put(SpringContextVariableNames.THYMELEAF_REQUEST_CONTEXT, thymeleafRequestContext);


		// Expose Thymeleaf's own evaluation context as a model variable
		//
		// Note Spring's EvaluationContexts are NOT THREAD-SAFE (in exchange for SpelExpressions being thread-safe).
		// That's why we need to create a new EvaluationContext for each request / template execution, even if it is
		// quite expensive to create because of requiring the initialization of several ConcurrentHashMaps.
		final ConversionService conversionService =
			applicationContext.containsBean(WEBFLUX_CONVERSION_SERVICE_NAME)?
				(ConversionService)applicationContext.getBean(WEBFLUX_CONVERSION_SERVICE_NAME): null;
		final ThymeleafEvaluationContext evaluationContext =
			new ThymeleafEvaluationContext(applicationContext, conversionService);
		mergedModel.put(ThymeleafEvaluationContext.THYMELEAF_EVALUATION_CONTEXT_CONTEXT_VARIABLE_NAME, evaluationContext);


		// Determine if we have a data-driver variable, and therefore will need to configure flushing of output chunks
		final boolean dataDriven = isDataDriven(mergedModel);


        /*
         * ----------------------------------------------------------------------------------------------------------
         * INSTANTIATION OF THE CONTEXT
         * ----------------------------------------------------------------------------------------------------------
         * - Once the model has been merged, we can create the Thymeleaf context object itself.
         * - The reason it is an ExpressionContext and not a Context is that before executing the template itself,
         *   we might need to use it for computing the markup selectors (if "template :: selector" was specified).
         * - The reason it is not a WebExpressionContext is that this class is linked to the Servlet API, which
         *   might not be present in a Spring WebFlux environment.
         * ----------------------------------------------------------------------------------------------------------
         */

		final IEngineConfiguration configuration = viewTemplateEngine.getConfiguration();
		final SpringWebFluxExpressionContext context =
			new SpringWebFluxExpressionContext(
				configuration, exchange, getReactiveAdapterRegistry(), getLocale(), mergedModel);


        /*
         * ----------------------------------------------------------------------------------------------------------
         * COMPUTATION OF (OPTIONAL) MARKUP SELECTORS
         * ----------------------------------------------------------------------------------------------------------
         * - If view name has been specified with a template selector (in order to execute only a fragment of
         *   the template) like "template :: selector", we will extract it and compute it.
         * ----------------------------------------------------------------------------------------------------------
         */

		final String templateName;
		final Set<String> markupSelectors;
		if (!viewTemplateName.contains("::")) {
			// No fragment specified at the template name

			templateName = viewTemplateName;
			markupSelectors = null;

		} else {
			// Template name contains a fragment name, so we should parse it as such

			final IStandardExpressionParser parser = StandardExpressions.getExpressionParser(configuration);

			final FragmentExpression fragmentExpression;
			try {
				// By parsing it as a standard expression, we might profit from the expression cache
				fragmentExpression = (FragmentExpression) parser.parseExpression(context, "~{" + viewTemplateName + "}");
			} catch (final TemplateProcessingException e) {
				return Mono.error(
					new IllegalArgumentException("Invalid template name specification: '" + viewTemplateName + "'"));
			}

			final FragmentExpression.ExecutedFragmentExpression fragment =
				FragmentExpression.createExecutedFragmentExpression(context, fragmentExpression, StandardExpressionExecutionContext.NORMAL);

			templateName = FragmentExpression.resolveTemplateName(fragment);
			markupSelectors = FragmentExpression.resolveFragments(fragment);
			final Map<String,Object> nameFragmentParameters = fragment.getFragmentParameters();

			if (nameFragmentParameters != null) {

				if (fragment.hasSyntheticParameters()) {
					// We cannot allow synthetic parameters because there is no way to specify them at the template
					// engine execution!
					return Mono.error(new IllegalArgumentException(
						"Parameters in a view specification must be named (non-synthetic): '" + viewTemplateName + "'"));
				}

				context.setVariables(nameFragmentParameters);

			}

		}

		final Set<String> processMarkupSelectors;
		if (markupSelectors != null && markupSelectors.size() > 0) {
			if (markupSelectorsToRender != null && markupSelectorsToRender.size() > 0) {
				return Mono.error(new IllegalArgumentException(
					"A markup selector has been specified (" + Arrays.asList(markupSelectors) + ") for a view " +
						"that was already being executed as a fragment (" + Arrays.asList(markupSelectorsToRender) + "). " +
						"Only one fragment selection is allowed."));
			}
			processMarkupSelectors = markupSelectors;
		} else {
			if (markupSelectorsToRender != null && markupSelectorsToRender.size() > 0) {
				processMarkupSelectors = markupSelectorsToRender;
			} else {
				processMarkupSelectors = null;
			}
		}


        /*
         * ----------------------------------------------------------------------------------------------------------
         * COMPUTATION OF TEMPLATE PROCESSING PARAMETERS AND HTTP HEADERS
         * ----------------------------------------------------------------------------------------------------------
         * - At this point we will compute the final values of the different parameters needed for processing the
         *   template (locale, encoding, buffer sizes, etc.)
         * ----------------------------------------------------------------------------------------------------------
         */

		final int templateResponseMaxChunkSizeBytes = getResponseMaxChunkSizeBytes();

		final HttpHeaders responseHeaders = exchange.getResponse().getHeaders();
		final Locale templateLocale = getLocale();
		if (templateLocale != null) {
			responseHeaders.setContentLanguage(templateLocale);
		}

		// Get the charset from the selected content type (or use default)
		final Charset charset = getCharset(contentType).orElse(getDefaultCharset());


        /*
         * -----------------------------------------------------------------------------------------------------------
         * SET (AND RETURN) THE TEMPLATE PROCESSING Flux<DataBuffer> OBJECTS
         * -----------------------------------------------------------------------------------------------------------
         * - There are three possible processing modes, for each of which a Publisher<DataBuffer> will be created in a
         *   different way:
         *
         *     1. FULL: Output chunks not limited in size (templateResponseMaxChunkSizeBytes == Integer.MAX_VALUE) and
         *        no data-driven execution (no context variable of type Publisher<X> driving the template engine
         *        execution): In this case Thymeleaf will be executed unthrottled, in full mode, writing output
         *        to a single DataBuffer chunk instanced before execution, and which will be passed to the output
         *        channels in a single onNext(buffer) call (immediately followed by onComplete()).
         *
         *     2. CHUNKED: Output chunks limited in size (responseMaxChunkSizeBytes) but no data-driven
         *        execution (no Publisher<X> driving engine execution). All model attributes are expected to be
         *        fully resolved (in a non-blocking fashion) by WebFlux before engine execution and the Thymeleaf
         *        engine will execute in throttled mode, performing a full-stop each time the chunk reaches the
         *        specified size, sending it to the output channels with onNext(chunk) and then waiting until
         *        these output channels make the engine resume its work with a new request(n) call. This
         *        execution mode will request an output flush from the server after producing each chunk.
         *
         *     3. DATA-DRIVEN: one of the model attributes is a Publisher<X> wrapped inside an implementation
         *        of the IReactiveDataDriverContextVariable<?> interface. In this case, the Thymeleaf engine will
         *        execute as a response to onNext(List<X>) events triggered by this Publisher. The
         *        "bufferSizeElements" specified at the model attribute will define the amount of elements
         *        produced by this Publisher that will be buffered into a List<X> before triggering the template
         *        engine each time (which is why Thymeleaf will react on onNext(List<X>) and not onNext(X)). Thymeleaf
         *        will expect to find a "th:each" iteration on the data-driven variable inside the processed template,
         *        and will be executed in throttled mode for the published elements, sending the resulting DataBuffer
         *        output chunks to the output channels via onNext(chunk) and stopping until a new onNext(List<X>)
         *        event is triggered. When execution is data-driven, a limit in size can be optionally specified for
         *        the output chunks (responseMaxChunkSizeBytes) which will make Thymeleaf never send
         *        to the output channels a chunk bigger than that (thus splitting the output generated for a List<X>
         *        of published elements into several chunks if required). When executing in DATA-DRIVEN mode,
         *        Thymeleaf will always request flushing of the output channels after producing each chunk.
         * ----------------------------------------------------------------------------------------------------------
         */


		final Publisher<DataBuffer> stream =
			viewTemplateEngine.processStream(
				templateName, processMarkupSelectors, context, response.bufferFactory(), contentType, charset,
				templateResponseMaxChunkSizeBytes); // FULL/DATADRIVEN if MAX_VALUE, CHUNKED/DATADRIVEN if other

		if (templateResponseMaxChunkSizeBytes == Integer.MAX_VALUE && !dataDriven) {

			// No size limit for output chunks has been set (FULL mode), so we will let the
			// server apply its standard behaviour ("writeWith").
			return response.writeWith(stream);

		}

		// Either we are in DATA-DRIVEN mode or a limit for output chunks has been set (CHUNKED mode), so we will
		// use "writeAndFlushWith" in order to make sure that output is flushed after each buffer.
		return response.writeAndFlushWith(Flux.from(stream).window(1));
	}



	private static boolean isDataDriven(final Map<String,Object> mergedModel) {
		if (mergedModel == null || mergedModel.size() == 0) {
			return false;
		}
		for (final Object value : mergedModel.values()) {
			if (value instanceof IReactiveDataDriverContextVariable) {
				return true;
			}
		}
		return false;
	}

	private ReactiveAdapterRegistry getReactiveAdapterRegistry() {

		final ApplicationContext applicationContext = getApplicationContext();
		if (applicationContext == null) {
			return null;
		}

		if (applicationContext != null) {
			try {
				return applicationContext.getBean(ReactiveAdapterRegistry.class);
			} catch (final NoSuchBeanDefinitionException ignored) {
				// No registry, but note that we can live without it (though limited to Flux and Mono)
			}
		}
		return null;

	}

	private static Optional<Charset> getCharset(final MediaType mediaType) {
		return mediaType != null ? Optional.ofNullable(mediaType.getCharset()) : Optional.empty();
	}
}
