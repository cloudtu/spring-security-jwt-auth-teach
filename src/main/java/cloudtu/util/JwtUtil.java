package cloudtu.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Component
public class JwtUtil {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);
    private static final String CLAIMS_KEY_USER_ROLES = "userRoles";

    private @Value("${jwt.signKey}") String jwtSignKey;
    private @Value("${jwt.expireTimeAsSec}") long jwtExpireTimeAsSec;

    public String createToken(String userName, List<String> userRoles){
        String token = Jwts.builder()
                .setSubject(userName)
                .addClaims(Map.of(CLAIMS_KEY_USER_ROLES, userRoles)) // 把 userRoles 也記錄進來
                .setIssuedAt(new Date()) //產生 JWT 的時間
                .setExpiration(Date.from(Instant.now().plusSeconds(jwtExpireTimeAsSec))) // JWT 過期時間
                .signWith(Keys.hmacShaKeyFor(jwtSignKey.getBytes(StandardCharsets.UTF_8)), SignatureAlgorithm.HS512)
                .compact();
        logger.debug("token : {}", token);
        return token;
    }


    /**
     * 當 token 解析失敗時，會丟出對應的 Exception。一般來說會遇到失敗是因為 token 過期、token 內容被竄改。
     *
     * @param token
     *
     * @return
     */
    private Claims parseToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(jwtSignKey.getBytes(StandardCharsets.UTF_8)))
                .build()
                .parseClaimsJws(token)
                .getBody();
        logger.debug("claims : {}", claims);
        return claims;
    }

    public String parseUserNameFromToken(String token) {
        return parseToken(token).getSubject();
    }

    public List<SimpleGrantedAuthority> parseUserAuthoritiesFromToken(String token) {
        List<String> userRoles = parseToken(token).get(CLAIMS_KEY_USER_ROLES, List.class);
        logger.debug("userRoles : {}", userRoles);
        return userRoles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
    }
}
