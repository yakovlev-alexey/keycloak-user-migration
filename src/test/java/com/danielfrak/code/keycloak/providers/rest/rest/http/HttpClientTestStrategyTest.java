package com.danielfrak.code.keycloak.providers.rest.rest.http;

import com.danielfrak.code.keycloak.providers.rest.rest.http.strategy.BasicAuthHttpClientStrategyBuilder;
import com.danielfrak.code.keycloak.providers.rest.rest.http.strategy.BearerTokenHttpClientStrategyBuilder;
import com.danielfrak.code.keycloak.providers.rest.rest.http.strategy.JwtAuthHttpClientStrategyBuilder;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.LaxRedirectStrategy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class HttpClientStrategyTest {

        private HttpClient httpClient;
        private MockWebServer mockWebServer;
        private String uri;

        @BeforeEach
        void setUp() throws IOException {
                mockWebServer = new MockWebServer();
                mockWebServer.start();
                httpClient = new HttpClient(HttpClientBuilder.create().setRedirectStrategy(new LaxRedirectStrategy()));
                uri = String.format("http://" + mockWebServer.getHostName() + ":%s/", mockWebServer.getPort());
        }

        @AfterEach
        void afterEach() throws IOException {
                mockWebServer.shutdown();
        }

        @ParameterizedTest
        @CsvSource(value = {
                        "null, null",
                        "null, somePassword",
                        "'', somePassword",
                        "' ', somePassword",
                        "someUser, null",
                        "someuser, ''",
                        "someuser, ' '"
        }, nullValues = "null")
        void shouldNotEnableBasicAuthIfCredentialsIncorrect(String basicAuthUser, String basicAuthPassword)
                        throws InterruptedException {
                var expectedBody = "anyBody";
                enqueueSuccessfulResponse(expectedBody);

                var strategy = BasicAuthHttpClientStrategyBuilder.create()
                                .setCredentials(basicAuthUser, basicAuthPassword).build();
                HttpResponse response = httpClient.get(uri, strategy);

                RecordedRequest recordedRequest = Objects.requireNonNull(
                                mockWebServer.takeRequest(5, TimeUnit.SECONDS));
                assertEquals(expectedBody, response.body);
                assertEquals(HttpGet.METHOD_NAME, recordedRequest.getMethod());
                assertEquals("/", recordedRequest.getPath());
                assertEquals(uri, Objects.requireNonNull(recordedRequest.getRequestUrl()).toString());
                assertNull(recordedRequest.getHeaders().get(HttpHeaders.AUTHORIZATION));
        }

        private void enqueueSuccessfulResponse(String body) {
                var mockResponse = new MockResponse()
                                .setBody(body)
                                .setResponseCode(HttpStatus.SC_OK);
                mockWebServer.enqueue(mockResponse);
        }

        @Test
        void shouldGetWithBasicAuth() throws InterruptedException {
                var expectedBody = "anyBody";
                enqueueSuccessfulResponse(expectedBody);
                var username = "username";
                var password = "password";

                var strategy = BasicAuthHttpClientStrategyBuilder.create()
                                .setCredentials(username, password).build();
                HttpResponse response = httpClient.get(uri, strategy);

                RecordedRequest recordedRequest = Objects
                                .requireNonNull(mockWebServer.takeRequest(5, TimeUnit.SECONDS));
                assertEquals(expectedBody, response.body);
                assertEquals(HttpGet.METHOD_NAME, recordedRequest.getMethod());
                assertEquals("/", recordedRequest.getPath());
                assertEquals(uri, Objects.requireNonNull(recordedRequest.getRequestUrl()).toString());
                String authorizationHeader = recordedRequest.getHeaders().get(HttpHeaders.AUTHORIZATION);
                assertNotNull(authorizationHeader);
                assertTrue(authorizationHeader.startsWith("Basic"));
                var expectedToken = new String(Base64.encodeBase64(String.format("%s:%s", username, password)
                                .getBytes(StandardCharsets.ISO_8859_1)));
                assertTrue(authorizationHeader.endsWith(expectedToken));
        }

        @ParameterizedTest
        @NullSource
        @ValueSource(strings = { "", " " })
        void shouldNotEnableBearerTokenAuthIfTokenIncorrect(String bearerToken)
                        throws InterruptedException {
                var expectedBody = "anyBody";
                enqueueSuccessfulResponse(expectedBody);

                var strategy = BearerTokenHttpClientStrategyBuilder.create()
                                .setToken(bearerToken).build();
                HttpResponse response = httpClient.get(uri, strategy);

                RecordedRequest recordedRequest = Objects
                                .requireNonNull(mockWebServer.takeRequest(5, TimeUnit.SECONDS));
                assertEquals(expectedBody, response.body);
                assertEquals(HttpGet.METHOD_NAME, recordedRequest.getMethod());
                assertEquals("/", recordedRequest.getPath());
                assertEquals(uri, Objects.requireNonNull(recordedRequest.getRequestUrl()).toString());
                assertNull(recordedRequest.getHeaders().get(HttpHeaders.AUTHORIZATION));
        }

        @Test
        void shouldGetWithBearerTokenAuth() throws InterruptedException {
                var expectedBody = "anyBody";
                enqueueSuccessfulResponse(expectedBody);
                var token = "token";

                var strategy = BearerTokenHttpClientStrategyBuilder.create()
                                .setToken(token).build();
                HttpResponse response = httpClient.get(uri, strategy);

                RecordedRequest recordedRequest = Objects
                                .requireNonNull(mockWebServer.takeRequest(5, TimeUnit.SECONDS));
                assertEquals(expectedBody, response.body);
                assertEquals(HttpGet.METHOD_NAME, recordedRequest.getMethod());
                assertEquals("/", recordedRequest.getPath());
                assertEquals(uri, Objects.requireNonNull(recordedRequest.getRequestUrl()).toString());
                String authorization = recordedRequest.getHeaders().get(HttpHeaders.AUTHORIZATION);
                assertNotNull(authorization);
                assertTrue(authorization.startsWith("Bearer"));
                assertTrue(authorization.endsWith(token));
        }

        @Test
        void shouldGetWithBearerJWTAuth() throws InterruptedException {
                var expectedBody = "anyBody";
                var subject = "johndoe";
                enqueueSuccessfulResponse(expectedBody);

                KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.RS256);

                PrivateKey privateKey = keyPair.getPrivate();

                var strategy = JwtAuthHttpClientStrategyBuilder.create()
                                .setSigningKey(privateKey).setSubject(subject).build();
                HttpResponse response = httpClient.get(uri, strategy);

                String jwt = Jwts.builder().setSubject(subject).signWith(privateKey).compact();

                RecordedRequest recordedRequest = Objects
                                .requireNonNull(mockWebServer.takeRequest(5, TimeUnit.SECONDS));
                assertEquals(expectedBody, response.body);
                assertEquals(HttpGet.METHOD_NAME, recordedRequest.getMethod());
                assertEquals("/", recordedRequest.getPath());
                assertEquals(uri, Objects.requireNonNull(recordedRequest.getRequestUrl()).toString());
                String authorization = recordedRequest.getHeaders().get(HttpHeaders.AUTHORIZATION);
                assertNotNull(authorization);
                assertTrue(authorization.startsWith("Bearer"));
                assertTrue(authorization.endsWith(jwt));
        }

        @Test
        void postShouldBeSentWithBasicAuthWhenBasicAuthIsEnabled() throws InterruptedException {
                var expectedBody = "anyBody";
                enqueueSuccessfulResponse(expectedBody);
                var username = "username";
                var password = "password";

                var strategy = BasicAuthHttpClientStrategyBuilder.create()
                                .setCredentials(username, password).build();
                HttpResponse response = httpClient.post(uri, expectedBody, strategy);

                var token = new String(Base64.encodeBase64(String.format("%s:%s", username, password)
                                .getBytes(StandardCharsets.ISO_8859_1)));
                RecordedRequest recordedRequest = Objects
                                .requireNonNull(mockWebServer.takeRequest(5, TimeUnit.SECONDS));
                var authorizationHeader = recordedRequest.getHeaders().get(HttpHeaders.AUTHORIZATION);
                assertEquals(expectedBody, response.body);
                assertEquals(HttpPost.METHOD_NAME, recordedRequest.getMethod());
                assertEquals("/", recordedRequest.getPath());
                assertEquals(uri, Objects.requireNonNull(recordedRequest.getRequestUrl()).toString());
                assertNotNull(authorizationHeader);
                assertTrue(authorizationHeader.startsWith("Basic"));
                assertTrue(authorizationHeader.endsWith(token));
        }

        @Test
        void postShouldBeSentWithBearerAuthWhenBasicAuthIsEnabled() throws InterruptedException {
                var expectedBody = "anyBody";
                var token = "token";
                enqueueSuccessfulResponse(expectedBody);

                var strategy = BearerTokenHttpClientStrategyBuilder.create()
                                .setToken(token).build();
                HttpResponse response = httpClient.post(uri, expectedBody, strategy);

                RecordedRequest recordedRequest = Objects.requireNonNull(
                                mockWebServer.takeRequest(5, TimeUnit.SECONDS));
                assertEquals(expectedBody, response.body);
                assertEquals(HttpPost.METHOD_NAME, recordedRequest.getMethod());
                assertEquals("/", recordedRequest.getPath());
                assertEquals(uri, Objects.requireNonNull(recordedRequest.getRequestUrl()).toString());
                String authorization = recordedRequest.getHeaders().get(HttpHeaders.AUTHORIZATION);
                assertNotNull(authorization);
                assertTrue(authorization.startsWith("Bearer"));
                assertTrue(authorization.endsWith(token));
        }

        @Test
        void postShouldBeSentWithBearerAuthWhenJWTIsEnabled() throws InterruptedException {
                var expectedBody = "anyBody";
                var subject = "johndoe";
                enqueueSuccessfulResponse(expectedBody);

                KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.RS256);

                PrivateKey privateKey = keyPair.getPrivate();

                var strategy = JwtAuthHttpClientStrategyBuilder.create()
                                .setSigningKey(privateKey).setSubject(subject).build();
                HttpResponse response = httpClient.post(uri, expectedBody, strategy);

                String jwt = Jwts.builder().setSubject(subject).signWith(privateKey).compact();

                RecordedRequest recordedRequest = Objects.requireNonNull(
                                mockWebServer.takeRequest(5, TimeUnit.SECONDS));
                assertEquals(expectedBody, response.body);
                assertEquals(HttpPost.METHOD_NAME, recordedRequest.getMethod());
                assertEquals("/", recordedRequest.getPath());
                assertEquals(uri, Objects.requireNonNull(recordedRequest.getRequestUrl()).toString());
                String authorization = recordedRequest.getHeaders().get(HttpHeaders.AUTHORIZATION);
                assertNotNull(authorization);
                assertTrue(authorization.startsWith("Bearer"));
                assertTrue(authorization.endsWith(jwt));
        }
}