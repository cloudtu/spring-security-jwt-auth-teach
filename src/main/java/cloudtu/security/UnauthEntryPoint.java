package cloudtu.security;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

/**
 * 存取到未授權的 restful api 時，會導到這個 class 進行後續處理
 */
public class UnauthEntryPoint implements AuthenticationEntryPoint {
    private static final Logger logger = LoggerFactory.getLogger(UnauthEntryPoint.class);

    // 用來處理 json <-> object 轉換。ObjectMapper class 會讀 POJO 裡的 @JsonIgnore, @JsonProperty annotation 設定
    private static final ObjectMapper jsonObjectMapper = new ObjectMapper();

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {
        logger.error(authException.getMessage(), authException);

        Map<String, String> errors = new LinkedHashMap<>();
        errors.put("error", authException.getMessage());

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        jsonObjectMapper.writeValue(response.getWriter(), errors);
    }

}