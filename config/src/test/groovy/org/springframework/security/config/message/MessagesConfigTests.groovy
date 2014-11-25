package org.springframework.security.config.message

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
import org.springframework.security.core.Authentication
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.stereotype.Controller
import org.springframework.web.socket.WebSocketHandler
import org.springframework.web.socket.server.HandshakeFailureException
import org.springframework.web.socket.server.HandshakeHandler

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
class MessagesConfigTests extends AbstractXmlConfigTests {
    Authentication messageUser

    def cleanup() {
        SecurityContextHolder.clearContext()
    }

    def 'messages with no id automatically integrates with clientInboundChannel'() {
        setup:
        messages {
            'message-interceptor'(pattern:'/permitAll',access:'permitAll')
            'message-interceptor'(pattern:'/denyAll',access:'denyAll')
        }


        when: 'message is sent to the denyAll endpoint'
        clientInboundChannel.send(message('/denyAll'))

        then: 'access is denied to the denyAll endpoint'
        def e = thrown(MessageDeliveryException)
        e.cause instanceof AccessDeniedException

        and: 'access is granted to the permitAll endpoint'
        clientInboundChannel.send(message('/permitAll'))
    }

    def 'messages with no id automatically adds Authentication argument resolver'() {
        setup:
        def id = 'authenticationController'
        bean(id,MyController)
        bean('inPostProcessor',InboundExecutorPostProcessor)
        messages {
            'message-interceptor'(pattern:'/**',access:'permitAll')
        }

        when: 'message is sent to the authentication endpoint'
        clientInboundChannel.send(message('/authentication'))

        then: 'the AuthenticationPrincipal is resolved'
        def controller = appContext.getBean(id)
        controller.authenticationPrincipal == messageUser.name
    }

    def 'messages with no id does not override customArgumentResolvers'() {
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
        messages {
            'message-interceptor'(pattern:'/**',access:'permitAll')
        }

        when: 'message is sent to the myCustom endpoint'
        clientInboundChannel.send(message('/myCustom'))

        then: 'myCustomArgument is resolved'
        def controller = appContext.getBean(id)
        controller.myCustomArgument!= null
    }

    def 'messages with id does not integrate with clientInboundChannel'() {
        setup:
        messages([id:'inCsi']) {
            'message-interceptor'(pattern:'/**',access:'denyAll')
        }

        when:
        def success = clientInboundChannel.send(message('/denyAll'))

        then:
        success

    }

    def 'messages with id can be explicitly integrated with clientInboundChannel'() {
        setup: 'message security explicitly setup'
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
        xml.messages(id:'inCsi') {
            'message-interceptor'(pattern:'/**',access:'denyAll')
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
        xml.messages {
            'message-interceptor'(pattern:'/denyAll',access:'denyAll')
            'message-interceptor'(pattern:'/permitAll',access:'permitAll')
        }
        createAppContext()
        ChannelInterceptor mci = appContext.getBean('mci')
        when:
        Message<?> message = message('/permitAll')
        clientInboundChannel.send(message)

        then:
        verify(mci).preSend(message, clientInboundChannel) || true

    }

    def messages(Map<String,Object> attrs=[:], Closure c) {
        bean('testHandler', TestHandshakeHandler)
        xml.'websocket:message-broker' {
            'websocket:transport' {}
            'websocket:stomp-endpoint'(path:'/app') {
                'websocket:handshake-handler'(ref:'testHandler') {}
            }
            'websocket:simple-broker'(prefix:"/queue, /topic"){}
        }
        xml.messages(attrs, c)
        createAppContext()
    }

    def getClientInboundChannel() {
        appContext.getBean("clientInboundChannel")
    }

    def message(String destination) {
        messageUser = new TestingAuthenticationToken('user','pass','ROLE_USER')
        SimpMessageHeaderAccessor headers = SimpMessageHeaderAccessor.create()
        headers.sessionId = '123'
        headers.sessionAttributes = [:]
        headers.destination = destination
        headers.user = messageUser
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
        @Override
        boolean doHandshake(ServerHttpRequest request, ServerHttpResponse response, WebSocketHandler wsHandler, Map<String, Object> attributes) throws HandshakeFailureException {
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
