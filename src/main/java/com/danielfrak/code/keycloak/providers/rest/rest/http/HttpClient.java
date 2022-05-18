package com.danielfrak.code.keycloak.providers.rest.rest.http;

import org.apache.http.HttpEntity;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import com.danielfrak.code.keycloak.providers.rest.rest.http.strategy.HttpClientStrategy;

public class HttpClient {

    private final HttpClientBuilder httpClientBuilder;

    public HttpClient(HttpClientBuilder httpClientBuilder) {
        this.httpClientBuilder = httpClientBuilder;
    }

    public HttpResponse get(String uri) {
        return get(uri, null);
    }

    public HttpResponse get(String uri, HttpClientStrategy strategy) {
        var request = new HttpGet(uri);
        return execute(request, strategy);
    }

    private HttpResponse execute(HttpUriRequest request, HttpClientStrategy strategy) {
        request.addHeader(HttpHeaders.ACCEPT, ContentType.APPLICATION_JSON.getMimeType());

        if (strategy != null) {
            strategy.configure(request);
        }

        try (
                CloseableHttpClient closeableHttpClient = httpClientBuilder.build();
                CloseableHttpResponse response = closeableHttpClient.execute(request)) {
            return getHttpResponse(response);
        } catch (IOException e) {
            throw new HttpRequestException(request, e);
        }
    }

    private HttpResponse getHttpResponse(CloseableHttpResponse response) throws IOException {
        int statusCode = response.getStatusLine().getStatusCode();
        if (statusCode != HttpStatus.SC_OK) {
            return new HttpResponse(statusCode);
        }

        String entityAsString = getEntityAsString(response);
        return new HttpResponse(statusCode, entityAsString);
    }

    private String getEntityAsString(CloseableHttpResponse response) throws IOException {
        HttpEntity entity = response.getEntity();
        Charset encoding = getEncoding(entity);
        return EntityUtils.toString(entity, encoding);
    }

    private Charset getEncoding(HttpEntity entity) {
        return Optional.ofNullable(ContentType.get(entity))
                .map(ContentType::getCharset)
                .orElse(StandardCharsets.UTF_8);
    }

    public HttpResponse post(String uri, String bodyAsJson) {
        return post(uri, bodyAsJson, null);
    }

    public HttpResponse post(String uri, String bodyAsJson, HttpClientStrategy strategy) {
        var request = new HttpPost(uri);
        var requestEntity = new StringEntity(bodyAsJson, ContentType.APPLICATION_JSON);
        request.setEntity(requestEntity);
        return execute(request, strategy);
    }

}