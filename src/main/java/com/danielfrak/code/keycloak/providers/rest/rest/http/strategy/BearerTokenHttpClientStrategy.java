package com.danielfrak.code.keycloak.providers.rest.rest.http.strategy;

import com.danielfrak.code.keycloak.providers.rest.rest.http.AuthorizationHeaderFormats;

import org.apache.http.HttpHeaders;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.message.BasicHeader;

public class BearerTokenHttpClientStrategy implements HttpClientStrategy {
        private BasicHeader authorizationHeader = null;

        public BearerTokenHttpClientStrategy(String token) {
                if (token == null || token.isBlank()) {
                        return;
                }

                authorizationHeader = new BasicHeader(HttpHeaders.AUTHORIZATION,
                                String.format(AuthorizationHeaderFormats.BEARER_FORMAT, token));
        }

        @Override
        public void configure(HttpUriRequest request) {
                if (authorizationHeader != null) {
                        request.setHeader(authorizationHeader);
                }
        }
}
