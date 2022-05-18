package com.danielfrak.code.keycloak.providers.rest.rest.http;

import com.danielfrak.code.keycloak.providers.rest.exceptions.RestUserProviderException;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import okhttp3.mockwebserver.SocketPolicy;
import okio.Buffer;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.LaxRedirectStrategy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import java.io.IOException;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class HttpClientTest {

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

        @Test
        void getShouldThrowIfResponseThrows() {
                var mockResponse = new MockResponse()
                                .setBody(new Buffer().write(new byte[4096]))
                                .setSocketPolicy(SocketPolicy.DISCONNECT_DURING_RESPONSE_BODY);
                mockWebServer.enqueue(mockResponse);

                assertThrows(RestUserProviderException.class, () -> httpClient.get(uri));
        }

        @Test
        void getShouldThrowIfRequestThrows() throws IOException {
                var httpClientBuilder = mock(HttpClientBuilder.class);
                var closeableHttpClient = mock(CloseableHttpClient.class);
                httpClient = new HttpClient(httpClientBuilder);

                when(httpClientBuilder.build())
                                .thenReturn(closeableHttpClient);
                when(closeableHttpClient.execute(any()))
                                .thenThrow(new IOException());

                assertThrows(RestUserProviderException.class, () -> httpClient.get(uri));
        }

        @Test
        void getShouldReturnResponseWhenHttpCodeNot200() throws InterruptedException {
                enqueueFailedResponse();

                HttpResponse response = httpClient.get(uri);

                RecordedRequest recordedRequest = Objects.requireNonNull(
                                mockWebServer.takeRequest(5, TimeUnit.SECONDS));
                assertNull(response.body);
                assertEquals(HttpGet.METHOD_NAME, recordedRequest.getMethod());
                assertEquals("/", recordedRequest.getPath());
                assertEquals(uri, Objects.requireNonNull(recordedRequest.getRequestUrl()).toString());
        }

        private void enqueueFailedResponse() {
                var mockResponse = new MockResponse()
                                .setBody("anyBody")
                                .setResponseCode(HttpStatus.SC_INTERNAL_SERVER_ERROR);
                mockWebServer.enqueue(mockResponse);
        }

        private void enqueueSuccessfulResponse(String body) {
                var mockResponse = new MockResponse()
                                .setBody(body)
                                .setResponseCode(HttpStatus.SC_OK);
                mockWebServer.enqueue(mockResponse);
        }

        @Test
        void getShouldSendAGetRequest() throws InterruptedException {
                var expectedBody = "anyBody";
                enqueueSuccessfulResponse(expectedBody);

                HttpResponse response = httpClient.get(uri);

                RecordedRequest recordedRequest = Objects.requireNonNull(
                                mockWebServer.takeRequest(5, TimeUnit.SECONDS));
                assertEquals(expectedBody, response.body);
                assertEquals(HttpGet.METHOD_NAME, recordedRequest.getMethod());
                assertEquals("/", recordedRequest.getPath());
                assertEquals(uri, Objects.requireNonNull(recordedRequest.getRequestUrl()).toString());
                assertNull(recordedRequest.getHeader(HttpHeaders.AUTHORIZATION));
        }

        @Test
        void getShouldHandleRedirectsWhenLaxRedirectStrategyIsUsed() throws InterruptedException {
                var expectedBody = "anyBody";
                var redirectedUri = uri + "redirected";

                mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.SC_MOVED_TEMPORARILY)
                                .setHeader("Location", redirectedUri));
                enqueueSuccessfulResponse(expectedBody);

                HttpResponse response = httpClient.get(uri);

                mockWebServer.takeRequest(5, TimeUnit.SECONDS);
                RecordedRequest recordedRequest = Objects.requireNonNull(
                                mockWebServer.takeRequest(5, TimeUnit.SECONDS));
                assertEquals(HttpGet.METHOD_NAME, recordedRequest.getMethod());
                assertEquals("/redirected", recordedRequest.getPath());
                assertEquals(redirectedUri, Objects.requireNonNull(recordedRequest.getRequestUrl()).toString());
                assertNull(recordedRequest.getHeader(HttpHeaders.AUTHORIZATION));

                assertEquals(expectedBody, response.body);
                assertEquals(HttpStatus.SC_OK, response.getCode());
        }

        @Test
        void getShouldSupportCustomResponseEncoding() throws InterruptedException {
                var expectedBody = "anyBody";
                var mockResponse = new MockResponse()
                                .setBody(expectedBody)
                                .addHeader("Content-Type", "ISO-8859-1")
                                .setResponseCode(HttpStatus.SC_OK);
                mockWebServer.enqueue(mockResponse);

                HttpResponse response = httpClient.get(uri);

                RecordedRequest recordedRequest = Objects.requireNonNull(
                                mockWebServer.takeRequest(5, TimeUnit.SECONDS));
                assertEquals(expectedBody, response.body);
                assertEquals(HttpGet.METHOD_NAME, recordedRequest.getMethod());
                assertEquals("/", recordedRequest.getPath());
                assertEquals(uri, Objects.requireNonNull(recordedRequest.getRequestUrl()).toString());
                assertNull(recordedRequest.getHeader(HttpHeaders.AUTHORIZATION));
        }

        @Test
        void postShouldThrowIfResponseThrows() {
                var mockResponse = new MockResponse()
                                .setBody(new Buffer().write(new byte[4096]))
                                .setSocketPolicy(SocketPolicy.DISCONNECT_DURING_RESPONSE_BODY);
                mockWebServer.enqueue(mockResponse);

                assertThrows(HttpRequestException.class, () -> httpClient.post(uri, "{}"));
        }

        @Test
        void postShouldThrowIfRequestThrows() throws IOException {
                var httpClientBuilder = mock(HttpClientBuilder.class);
                var closeableHttpClient = mock(CloseableHttpClient.class);
                httpClient = new HttpClient(httpClientBuilder);

                when(httpClientBuilder.build())
                                .thenReturn(closeableHttpClient);
                when(closeableHttpClient.execute(any()))
                                .thenThrow(new IOException());

                assertThrows(RestUserProviderException.class, () -> httpClient.post(uri, "{}"));
        }

        @Test
        void postShouldSendAPostRequest() throws InterruptedException {
                var expectedBody = "anyBody";
                enqueueSuccessfulResponse(expectedBody);

                HttpResponse response = httpClient.post(uri, expectedBody);

                RecordedRequest recordedRequest = Objects.requireNonNull(
                                mockWebServer.takeRequest(5, TimeUnit.SECONDS));
                assertEquals(expectedBody, response.body);
                assertEquals(HttpPost.METHOD_NAME, recordedRequest.getMethod());
                assertEquals("/", recordedRequest.getPath());
                assertEquals(uri, Objects.requireNonNull(recordedRequest.getRequestUrl()).toString());
        }

        @Test
        void postShouldHandleRedirectsWhenLaxRedirectStrategyIsUsed() throws InterruptedException {
                var expectedBody = "anyBody";
                var redirectedUri = uri + "redirected";

                mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.SC_TEMPORARY_REDIRECT)
                                .setHeader("Location", redirectedUri));
                enqueueSuccessfulResponse(expectedBody);

                HttpResponse response = httpClient.post(uri, "{}");

                mockWebServer.takeRequest(5, TimeUnit.SECONDS);
                RecordedRequest recordedRequest = Objects.requireNonNull(
                                mockWebServer.takeRequest(5, TimeUnit.SECONDS));
                assertEquals(HttpPost.METHOD_NAME, recordedRequest.getMethod());
                assertEquals("/redirected", recordedRequest.getPath());
                assertEquals(redirectedUri, Objects.requireNonNull(recordedRequest.getRequestUrl()).toString());
                assertNull(recordedRequest.getHeader(HttpHeaders.AUTHORIZATION));

                assertEquals(expectedBody, response.body);
                assertEquals(HttpStatus.SC_OK, response.getCode());
        }

        @Test
        void postShouldSupportCustomResponseEncoding() throws InterruptedException {
                var expectedBody = "anyBody";
                var mockResponse = new MockResponse()
                                .setBody(expectedBody)
                                .addHeader("Content-Type", "ISO-8859-1")
                                .setResponseCode(HttpStatus.SC_OK);
                mockWebServer.enqueue(mockResponse);

                HttpResponse response = httpClient.post(uri, expectedBody);

                RecordedRequest recordedRequest = Objects.requireNonNull(
                                mockWebServer.takeRequest(5, TimeUnit.SECONDS));
                assertEquals(expectedBody, response.body);
                assertEquals(HttpPost.METHOD_NAME, recordedRequest.getMethod());
                assertEquals("/", recordedRequest.getPath());
                assertEquals(uri, Objects.requireNonNull(recordedRequest.getRequestUrl()).toString());
        }

        @Test
        void postShouldReturnResponseWhenHttpCodeNot200() throws InterruptedException {
                enqueueFailedResponse();

                HttpResponse response = httpClient.post(uri, "{}");

                RecordedRequest recordedRequest = Objects.requireNonNull(
                                mockWebServer.takeRequest(5, TimeUnit.SECONDS));
                assertNull(response.body);
                assertEquals(HttpPost.METHOD_NAME, recordedRequest.getMethod());
                assertEquals("/", recordedRequest.getPath());
                assertEquals(uri, Objects.requireNonNull(recordedRequest.getRequestUrl()).toString());
        }
}