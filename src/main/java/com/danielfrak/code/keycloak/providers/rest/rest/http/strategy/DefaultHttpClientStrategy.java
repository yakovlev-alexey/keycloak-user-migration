package com.danielfrak.code.keycloak.providers.rest.rest.http.strategy;

import org.apache.http.client.methods.HttpUriRequest;

public final class DefaultHttpClientStrategy implements HttpClientStrategy {

        @Override
        public void configure(HttpUriRequest request) {
                // Do not need to modify the request by default
        }
}
