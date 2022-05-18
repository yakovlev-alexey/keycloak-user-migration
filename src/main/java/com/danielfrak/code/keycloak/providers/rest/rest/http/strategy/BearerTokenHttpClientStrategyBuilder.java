package com.danielfrak.code.keycloak.providers.rest.rest.http.strategy;

public class BearerTokenHttpClientStrategyBuilder implements HttpClientStrategyBuilder {
        private BearerTokenHttpClientStrategy instance = null;

        private BearerTokenHttpClientStrategyBuilder() {
                instance = new BearerTokenHttpClientStrategy(null);
        }

        public static BearerTokenHttpClientStrategyBuilder create() {
                return new BearerTokenHttpClientStrategyBuilder();
        }

        public BearerTokenHttpClientStrategyBuilder setToken(String token) {
                instance = new BearerTokenHttpClientStrategy(token);

                return this;
        }

        public BearerTokenHttpClientStrategy build() {
                return instance;
        }
}
