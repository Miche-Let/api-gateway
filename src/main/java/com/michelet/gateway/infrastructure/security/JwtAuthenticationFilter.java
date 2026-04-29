package com.michelet.gateway.infrastructure.security;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {
    private static final String USER_ID_HEADER = "X-User-Id";
    private static final String USER_ROLE_HEADER = "X-User-Role";


    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .map(securityContext -> securityContext.getAuthentication())
                .flatMap(authentication -> addHeaders(authentication, exchange,chain))
                .switchIfEmpty(chain.filter(exchange))
                .onErrorResume(ex-> chain.filter(exchange));
    }

    public Mono<Void> addHeaders(
            Authentication authentication,
            ServerWebExchange exchange,
            GatewayFilterChain chain
    ){
        if(!(authentication instanceof JwtAuthenticationToken))
            return chain.filter(exchange);
        Jwt jwt = ((JwtAuthenticationToken) authentication).getToken();

        ServerHttpRequest mutatedRequest = exchange.getRequest()
                .mutate()
                .header(USER_ID_HEADER, normalize(jwt.getSubject()))
                .header(USER_ROLE_HEADER, normalize(jwt.getClaimAsString("role")))
                .build();

        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }

    @Override
    public int getOrder() {
        return Ordered.LOWEST_PRECEDENCE - 5;
    }

    private String normalize(String value){
        return value == null ? "" : value;
    }
}
