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
                .flatMap(securityContext -> {
                    Authentication authentication = securityContext.getAuthentication();
                    if(authentication == null){
                        return chain.filter(exchange);
                    }
                    return addHeaders(authentication,exchange,chain);
                })
                .switchIfEmpty(chain.filter(exchange));
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
                .headers(
                        httpHeaders -> {
                            httpHeaders.remove(USER_ID_HEADER);
                            httpHeaders.remove(USER_ROLE_HEADER);

                            String userId = jwt.getSubject();
                            if (userId != null && !userId.isBlank()) {
                                httpHeaders.set(USER_ID_HEADER, userId);
                            }

                            String role = jwt.getClaimAsString("role");
                            if (role != null && !role.isBlank()) {
                                httpHeaders.set(USER_ROLE_HEADER, role);
                            }
                        }
                )
                .build();

        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }

    @Override
    public int getOrder() {
        return Ordered.LOWEST_PRECEDENCE - 5;
    }

}
