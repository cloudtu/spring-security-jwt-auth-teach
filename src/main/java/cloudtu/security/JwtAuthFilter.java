package cloudtu.security;

import cloudtu.util.JwtUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 這個 filter 利用 http request header 帶的 JWT(Json Web Token) 進行用戶認証與授權
 */
@Component
public class JwtAuthFilter extends OncePerRequestFilter {
    private static final Logger logger = LoggerFactory.getLogger(JwtAuthFilter.class);

    // 用來處理 json <-> object 轉換。ObjectMapper class 會讀 POJO 裡的 @JsonIgnore, @JsonProperty annotation 設定
    private static final ObjectMapper jsonObjectMapper = new ObjectMapper();

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            String token = retriveJwt(request);
            if (token != null){
                // 因為 WebSecurityConfig 設定 sessionCreationPolicy(SessionCreationPolicy.STATELESS)，所以
                // 不用 http session 記錄資料，因此 SecurityContextHolder 不會將登入認証成功後的 Authentication 記到
                // http session。也就是說登入認証成功後的 Authentication 不會被記錄到系統，每次的 http request 都必需重新
                // 進行一次登入認証，不然從 SecurityContextHolder.getContext().getAuthentication() 取回登入認証成功後
                // 的 Authentication instance 一定是 null。

                //region 當 token 變數可以成功解析出 userName 與 userRoles 時，代表是合法 token，這時可以用 token 裡的資料產生
                //       登入認証成功後的 Authentication，並將它存放到 SecurityContextHolder.getContext().setAuthentication(...) method
                //       讓系統知道用戶已登入認証成功
                String userName = jwtUtil.parseUserNameFromToken(token); // 解析失敗時會丟出 exception
                List<SimpleGrantedAuthority> userAuthorities = jwtUtil.parseUserAuthoritiesFromToken(token); // 解析失敗時會丟出 exception
                UserDetails userDetails = new UserDetailsImpl(userName, null, userAuthorities); // 因為 token 裡不會記錄 password, 所以 constructor 裡的 password 欄位帶入 null

                // 如果想讓系統更安全，可以用 token 取得的 userName 反查 userDetailsService 之後產生 UserDetails instance
                // 但是 userDetailsService 的實作大多是到 DB 查資料，如果 http request 數量很大的話，要考慮幫它加上 cache 机制降低 DB 負擔
                // UserDetails userDetails = userDetailsService.loadUserByUsername(userName);

                UsernamePasswordAuthenticationToken authAfterSuccessLogin = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authAfterSuccessLogin.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authAfterSuccessLogin);
                //endregion
            }
        }
        catch (Exception e) {
            logger.error(e.getMessage(), e);

            Map<String, String> errorMsg = new LinkedHashMap<>();
            errorMsg.put("error", e.getMessage());

            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            jsonObjectMapper.writeValue(response.getWriter(), errorMsg);
            return;
        }

        filterChain.doFilter(request, response);
    }

    /**
     * 從 http header 取出 JWT(Json Web Token)
     *
     * @param request
     *
     * @return 取不到 JWT 時回傳 null
     */
    private String retriveJwt(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");

        if (authHeader != null && !authHeader.isBlank() && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }

        return null;
    }
}
