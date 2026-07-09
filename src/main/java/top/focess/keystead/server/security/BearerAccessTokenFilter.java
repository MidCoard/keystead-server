package top.focess.keystead.server.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public final class BearerAccessTokenFilter extends OncePerRequestFilter {

    private static final String BEARER_PREFIX = "Bearer ";

    private final AccessTokenService accessTokens;

    public BearerAccessTokenFilter(@NonNull AccessTokenService accessTokens) {
        this.accessTokens = accessTokens;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        @Nullable String authorization = request.getHeader("Authorization");
        if (authorization != null
                && authorization.startsWith(BEARER_PREFIX)
                && SecurityContextHolder.getContext().getAuthentication() == null) {
            accessTokens
                    .authenticate(authorization.substring(BEARER_PREFIX.length()))
                    .ifPresent(
                            username ->
                                    SecurityContextHolder.getContext()
                                            .setAuthentication(
                                                    new UsernamePasswordAuthenticationToken(
                                                            username,
                                                            "N/A",
                                                            AuthorityUtils.createAuthorityList(
                                                                    "ROLE_USER"))));
        }
        filterChain.doFilter(request, response);
    }
}
