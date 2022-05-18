package com.danielfrak.code.keycloak.providers.rest.rest.http.strategy;

public class DefaultHttpClientStrategyBuilder implements HttpClientStrategyBuilder {
        private DefaultHttpClientStrategyBuilder() {
        }

        public static DefaultHttpClientStrategyBuilder create() {
                return new DefaultHttpClientStrategyBuilder();
        }

        public DefaultHttpClientStrategy build() {
                return new DefaultHttpClientStrategy();
        }
}
