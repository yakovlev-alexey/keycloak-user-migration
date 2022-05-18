package com.danielfrak.code.keycloak.providers.rest.rest.http.strategy;

import org.apache.http.client.methods.HttpUriRequest;

public interface HttpClientStrategy {
        public void configure(HttpUriRequest request);
}
