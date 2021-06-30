package org.wildfly.httpclient.common;

import io.undertow.client.ClientRequest;
import io.undertow.client.ClientResponse;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.util.Headers;
import io.undertow.util.Methods;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import javax.json.Json;
import javax.json.JsonObjectBuilder;
import java.io.Closeable;
import java.io.InputStream;
import java.net.URI;
import java.util.Locale;
import java.util.concurrent.CompletableFuture;

/**
 * Tests Bearer token HTTP authentication
 */
@SuppressWarnings({"Convert2Lambda"})
@RunWith(HTTPTestServer.class)
public class BearerTokenAuthenticationTestCase {

    private static final JwtManager jwtManager = new JwtManager();

    @Before
    public void setUp() {
        HTTPTestServer.registerPathHandler("/private-res", new HttpHandler() {
            @Override
            public void handleRequest(HttpServerExchange exchange) {
                String auth = exchange.getRequestHeaders().getFirst("Authorization");
                try {
                    boolean authed = false;
                    if (auth != null && auth.toLowerCase(Locale.US).startsWith("bearer ")) {
                        String token = auth.substring(7);
                        authed = jwtManager.verify(token);
                    }
                    if (!authed) {
                        // pretend authentication failure
                        exchange.setStatusCode(401);
                        exchange.getResponseHeaders().add(Headers.CONTENT_TYPE, "text/html");
                        exchange.getResponseHeaders().add(Headers.WWW_AUTHENTICATE, "bearer realm=jwt-token");
                    } else {
                        exchange.setStatusCode(200);
                        exchange.getResponseHeaders().add(Headers.CONTENT_TYPE, "text/html");
                        exchange.getResponseSender().send("Hello there");
                    }
                } catch (Exception e) {
                    exchange.setStatusCode(500);
                    exchange.getResponseSender().send(e.getMessage());
                }
            }
        });
        HTTPTestServer.registerPathHandler("/jwt-token", new HttpHandler() {
            @Override
            public void handleRequest(HttpServerExchange exchange) {
                // acts as token endpoint
                try {
                    String token = jwtManager.createJwt("sub", new String[]{"admin"});
                    exchange.setStatusCode(200);
                    exchange.getResponseHeaders().add(Headers.CONTENT_TYPE, "text/html");
                    JsonObjectBuilder tokenBuilder = Json.createObjectBuilder();
                    tokenBuilder.add("access_token", token);
                    exchange.getResponseSender().send(tokenBuilder.build().toString());
                } catch (Exception e) {
                    e.printStackTrace();
                    exchange.setStatusCode(500);
                    exchange.getResponseHeaders().add(Headers.CONTENT_TYPE, "text/html");
                }
            }
        });
    }

    @Test
    public void testBearerToken() throws Exception {
        System.setProperty("wildfly.config.url", "src/test/resources/wildfly-config-bearer.xml");
        ClientRequest request = new ClientRequest().setMethod(Methods.GET).setPath("/private-res");
        CompletableFuture<ClientResponse> responseFuture = new CompletableFuture<>();
        HttpTargetContext context = WildflyHttpContext.getCurrent().getTargetContext(new URI(HTTPTestServer.getDefaultServerURL()));
        context.sendRequest(request, null, null, null,
                new HttpTargetContext.HttpResultHandler() {
                    @Override
                    public void handleResult(InputStream result, ClientResponse response, Closeable doneCallback) {
                        responseFuture.complete(response);
                    }
                }, new HttpTargetContext.HttpFailureHandler() {
                    @Override
                    public void handleFailure(Throwable throwable) {
                        throwable.printStackTrace();
                        responseFuture.completeExceptionally(throwable);
                    }
                },
                new ContentType("text/html", 1), null, true);
        ClientResponse response = responseFuture.get();
        Assert.assertNotNull(response);
        Assert.assertEquals(200, response.getResponseCode());
    }

}
