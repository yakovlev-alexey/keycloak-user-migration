package com.danielfrak.code.keycloak.providers.rest.rest.http.strategy;

public class BasicAuthHttpClientStrategyBuilder implements HttpClientStrategyBuilder {
        private BasicAuthHttpClientStrategy instance = null;

        private BasicAuthHttpClientStrategyBuilder() {
                instance = new BasicAuthHttpClientStrategy(null, null);
        }

        public static BasicAuthHttpClientStrategyBuilder create() {
                return new BasicAuthHttpClientStrategyBuilder();
        }

        public BasicAuthHttpClientStrategyBuilder setCredentials(String user, String password) {
                instance = new BasicAuthHttpClientStrategy(user, password);

                return this;
        }

        public BasicAuthHttpClientStrategy build() {
                return instance;
        }
}
