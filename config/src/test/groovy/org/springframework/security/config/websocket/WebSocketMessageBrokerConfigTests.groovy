package org.springframework.security.config.websocket

import org.springframework.beans.BeansException
import org.springframework.beans.factory.config.BeanDefinition
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory
import org.springframework.beans.factory.support.BeanDefinitionRegistry
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor
import org.springframework.beans.factory.support.RootBeanDefinition
import org.springframework.core.MethodParameter
import org.springframework.core.task.SyncTaskExecutor
import org.springframework.http.server.ServerHttpRequest
import org.springframework.http.server.ServerHttpResponse
import org.springframework.messaging.handler.annotation.MessageMapping
import org.springframework.messaging.handler.invocation.HandlerMethodArgumentResolver
import org.springframework.messaging.simp.SimpMessageType
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.core.Authentication
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.web.csrf.CsrfToken
import org.springframework.security.web.csrf.DefaultCsrfToken
import org.springframework.security.web.csrf.MissingCsrfTokenException
import org.springframework.stereotype.Controller
import org.springframework.web.servlet.HandlerMapping
import org.springframework.web.servlet.handler.SimpleUrlHandlerMapping
import org.springframework.web.socket.WebSocketHandler
import org.springframework.web.socket.server.HandshakeFailureException
import org.springframework.web.socket.server.HandshakeHandler
import org.springframework.web.socket.server.support.HttpSessionHandshakeInterceptor
import org.springframework.web.socket.server.support.WebSocketHttpRequestHandler
import org.springframework.web.socket.sockjs.support.SockJsHttpRequestHandler
import org.springframework.web.socket.sockjs.transport.handler.SockJsWebSocketHandler

import static org.mockito.Mockito.*

import org.springframework.messaging.Message
import org.springframework.messaging.MessageDeliveryException
import org.springframework.messaging.simp.SimpMessageHeaderAccessor
import org.springframework.messaging.support.ChannelInterceptor
import org.springframework.messaging.support.GenericMessage
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.config.AbstractXmlConfigTests
import org.springframework.security.core.context.SecurityContextHolder

/**
 *
 * @author Rob Winch
 */
class WebSocketMessageBrokerConfigTests extends AbstractXmlConfigTests {
    Authentication messageUser = new TestingAuthenticationToken('user','pass','ROLE_USER')
    boolean useSockJS = false

    def cleanup() {
        SecurityContextHolder.clearContext()
    }

    def 'websocket with no id automatically integrates with clientInboundChannel'() {
        setup:
        websocket {
            'intercept-message'(pattern:'/permitAll',access:'permitAll')
            'intercept-message'(pattern:'/denyAll',access:'denyAll')
        }


        when: 'message is sent to the denyAll endpoint'
        clientInboundChannel.send(message('/denyAll'))

        then: 'access is denied to the denyAll endpoint'
        def e = thrown(MessageDeliveryException)
        e.cause instanceof AccessDeniedException

        and: 'access is granted to the permitAll endpoint'
        clientInboundChannel.send(message('/permitAll'))
    }

    def 'anonymous authentication supported'() {
        setup:
        websocket {
            'intercept-message'(pattern:'/permitAll',access:'permitAll')
            'intercept-message'(pattern:'/denyAll',access:'denyAll')
        }
        messageUser = null

        when: 'message is sent to the permitAll endpoint with no user'
        clientInboundChannel.send(message('/permitAll'))

        then: 'access is granted'
        noExceptionThrown()
    }

    def 'messages with no id automatically adds Authentication argument resolver'() {
        setup:
        def id = 'authenticationController'
        bean(id,MyController)
        bean('inPostProcessor',InboundExecutorPostProcessor)
        websocket {
            'intercept-message'(pattern:'/**',access:'permitAll')
        }

        when: 'message is sent to the authentication endpoint'
        clientInboundChannel.send(message('/authentication'))

        then: 'the AuthenticationPrincipal is resolved'
        def controller = appContext.getBean(id)
        controller.authenticationPrincipal == messageUser.name
    }

    def 'messages of type CONNECT use CsrfTokenHandshakeInterceptor'() {
        setup:
        def id = 'authenticationController'
        bean(id,MyController)
        bean('inPostProcessor',InboundExecutorPostProcessor)
        websocket {
            'intercept-message'(pattern:'/**',access:'permitAll')
        }

        SimpMessageHeaderAccessor headers = SimpMessageHeaderAccessor.create(SimpMessageType.CONNECT)
        Message<?> message = message(headers,'/authentication')
        WebSocketHttpRequestHandler handler = appContext.getBean(WebSocketHttpRequestHandler)
        MockHttpServletRequest request = new MockHttpServletRequest()
        String sessionAttr = "sessionAttr"
        request.getSession().setAttribute(sessionAttr,"sessionValue")

        CsrfToken token = new DefaultCsrfToken("header", "param", "token")
        request.setAttribute(CsrfToken.name, token)

        when:
        handler.handleRequest(request , new MockHttpServletResponse())
        TestHandshakeHandler handshakeHandler = appContext.getBean(TestHandshakeHandler)

        then: 'CsrfToken is populated'
        handshakeHandler.attributes.get(CsrfToken.name) == token

        and: 'Explicitly listed HandshakeInterceptor are not overridden'
        handshakeHandler.attributes.get(sessionAttr) == request.getSession().getAttribute(sessionAttr)
    }

    def 'messages of type CONNECT use CsrfTokenHandshakeInterceptor with SockJS'() {
        setup:
        useSockJS = true
        def id = 'authenticationController'
        bean(id,MyController)
        bean('inPostProcessor',InboundExecutorPostProcessor)
        websocket {
            'intercept-message'(pattern:'/**',access:'permitAll')
        }

        SimpMessageHeaderAccessor headers = SimpMessageHeaderAccessor.create(SimpMessageType.CONNECT)
        Message<?> message = message(headers,'/authentication')
        SockJsHttpRequestHandler handler = appContext.getBean(SockJsHttpRequestHandler)
        MockHttpServletRequest request = new MockHttpServletRequest()
        String sessionAttr = "sessionAttr"
        request.getSession().setAttribute(sessionAttr,"sessionValue")

        CsrfToken token = new DefaultCsrfToken("header", "param", "token")
        request.setAttribute(CsrfToken.name, token)

        request.setMethod("GET")
        request.setAttribute(HandlerMapping.PATH_WITHIN_HANDLER_MAPPING_ATTRIBUTE, "/289/tpyx6mde/websocket")

        when:
        handler.handleRequest(request , new MockHttpServletResponse())
        TestHandshakeHandler handshakeHandler = appContext.getBean(TestHandshakeHandler)

        then: 'CsrfToken is populated'
        handshakeHandler.attributes?.get(CsrfToken.name) == token

        and: 'Explicitly listed HandshakeInterceptor are not overridden'
        handshakeHandler.attributes?.get(sessionAttr) == request.getSession().getAttribute(sessionAttr)
    }

    def 'messages of type CONNECT require valid CsrfToken'() {
        setup:
        def id = 'authenticationController'
        bean(id,MyController)
        bean('inPostProcessor',InboundExecutorPostProcessor)
        websocket {
            'intercept-message'(pattern:'/**',access:'permitAll')
        }

        when: 'websocket of type CONNECTION is sent without CsrfTOken'
        SimpMessageHeaderAccessor headers = SimpMessageHeaderAccessor.create(SimpMessageType.CONNECT)
        Message<?> message = message(headers,'/authentication')
        clientInboundChannel.send(message)

        then: 'CSRF Protection blocks the Message'
        MessageDeliveryException expected = thrown()
        expected.cause instanceof MissingCsrfTokenException
    }

    def 'websocket with no id does not override customArgumentResolvers'() {
        setup:
        def id = 'authenticationController'
        bean(id,MyController)
        bean('inPostProcessor',InboundExecutorPostProcessor)
        bean('mcar', MyCustomArgumentResolver)
        xml.'websocket:message-broker' {
            'websocket:transport' {}
            'websocket:stomp-endpoint'(path:'/app') {
                'websocket:handshake-handler'(ref:'testHandler') {}
            }
            'websocket:simple-broker'(prefix:"/queue, /topic"){}
            'websocket:argument-resolvers' {
                'b:ref'(bean:'mcar')
            }
        }
        websocket {
            'intercept-message'(pattern:'/**',access:'permitAll')
        }

        when: 'websocket is sent to the myCustom endpoint'
        clientInboundChannel.send(message('/myCustom'))

        then: 'myCustomArgument is resolved'
        def controller = appContext.getBean(id)
        controller.myCustomArgument!= null
    }

    def 'websocket with id does not integrate with clientInboundChannel'() {
        setup:
        websocket([id:'inCsi']) {
            'intercept-message'(pattern:'/**',access:'denyAll')
        }

        when:
        def success = clientInboundChannel.send(message('/denyAll'))

        then:
        success

    }

    def 'websocket with id can be explicitly integrated with clientInboundChannel'() {
        setup: 'websocket security explicitly setup'
        xml.'websocket:message-broker' {
            'websocket:transport' {}
            'websocket:stomp-endpoint'(path:'/app') {
                'websocket:sockjs' {}
            }
            'websocket:simple-broker'(prefix:"/queue, /topic"){}
            'websocket:client-inbound-channel' {
                'websocket:interceptors' {
                    'b:bean'(class:'org.springframework.security.messaging.context.SecurityContextChannelInterceptor'){}
                    'b:ref'(bean:'inCsi'){}
                }
            }
        }
        xml.'websocket-message-broker'(id:'inCsi') {
            'intercept-message'(pattern:'/**',access:'denyAll')
        }
        createAppContext()

        when:
        clientInboundChannel.send(message('/denyAll'))

        then:
        def e = thrown(MessageDeliveryException)
        e.cause instanceof AccessDeniedException

    }

    def 'automatic integration with clientInboundChannel does not override exisiting websocket:interceptors'() {
        setup:
        mockBean(ChannelInterceptor,'mci')
        xml.'websocket:message-broker'('application-destination-prefix':'/app',
                                        'user-destination-prefix':'/user') {
            'websocket:transport' {}
            'websocket:stomp-endpoint'(path:'/foo') {
                'websocket:sockjs' {}
            }
            'websocket:simple-broker'(prefix:"/queue, /topic"){}
            'websocket:client-inbound-channel' {
                'websocket:interceptors' {
                    'b:ref'(bean:'mci'){}
                }
            }
        }
        xml.'websocket-message-broker' {
            'intercept-message'(pattern:'/denyAll',access:'denyAll')
            'intercept-message'(pattern:'/permitAll',access:'permitAll')
        }
        createAppContext()
        ChannelInterceptor mci = appContext.getBean('mci')
        when:
        Message<?> message = message('/permitAll')
        clientInboundChannel.send(message)

        then:
        verify(mci).preSend(message, clientInboundChannel) || true

    }

    def websocket(Map<String,Object> attrs=[:], Closure c) {
        bean('testHandler', TestHandshakeHandler)
        xml.'websocket:message-broker' {
            'websocket:transport' {}
            'websocket:stomp-endpoint'(path:'/app') {
                'websocket:handshake-handler'(ref:'testHandler') {}
                'websocket:handshake-interceptors' {
                    'b:bean'('class':HttpSessionHandshakeInterceptor.name) {}
                }
                if(useSockJS) {
                    'websocket:sockjs' {}
                }
            }
            'websocket:simple-broker'(prefix:"/queue, /topic"){}
        }
        xml.'websocket-message-broker'(attrs, c)
        createAppContext()
    }

    def getClientInboundChannel() {
        appContext.getBean("clientInboundChannel")
    }

    def message(String destination) {
        SimpMessageHeaderAccessor headers = SimpMessageHeaderAccessor.create()
        message(headers, destination)
    }

    def message(SimpMessageHeaderAccessor headers, String destination) {
        messageUser = new TestingAuthenticationToken('user','pass','ROLE_USER')
        headers.sessionId = '123'
        headers.sessionAttributes = [:]
        headers.destination = destination
        if(messageUser != null) {
            headers.user = messageUser
        }
        new GenericMessage<String>("hi",headers.messageHeaders)
    }

    @Controller
    static class MyController {
        String authenticationPrincipal
        MyCustomArgument myCustomArgument

        @MessageMapping('/authentication')
        public void authentication(@AuthenticationPrincipal String un) {
            this.authenticationPrincipal = un
        }

        @MessageMapping('/myCustom')
        public void myCustom(MyCustomArgument myCustomArgument) {
            this.myCustomArgument = myCustomArgument
        }
    }

    static class MyCustomArgument {
        MyCustomArgument(String notDefaultConstr) {}
    }

    static class MyCustomArgumentResolver implements HandlerMethodArgumentResolver {

        @Override
        boolean supportsParameter(MethodParameter parameter) {
            parameter.parameterType.isAssignableFrom(MyCustomArgument)
        }

        @Override
        Object resolveArgument(MethodParameter parameter, Message<?> message) throws Exception {
            new MyCustomArgument("")
        }
    }

    static class TestHandshakeHandler implements HandshakeHandler {
        Map<String, Object> attributes;

        boolean doHandshake(ServerHttpRequest request, ServerHttpResponse response, WebSocketHandler wsHandler, Map<String, Object> attributes) throws HandshakeFailureException {
            this.attributes = attributes
            if(wsHandler instanceof SockJsWebSocketHandler) {
                // work around SPR-12716
                SockJsWebSocketHandler sockJs = (SockJsWebSocketHandler) wsHandler;
                this.attributes = sockJs.sockJsSession.attributes
            }
            true
        }
    }

    /**
     * Changes the clientInboundChannel Executor to be synchronous
     */
    static class InboundExecutorPostProcessor implements BeanDefinitionRegistryPostProcessor {

        @Override
        void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) throws BeansException {
            BeanDefinition inbound = registry.getBeanDefinition("clientInboundChannel")
            inbound.getConstructorArgumentValues().addIndexedArgumentValue(0, new RootBeanDefinition(SyncTaskExecutor));
        }

        @Override
        void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {

        }
    }
}
