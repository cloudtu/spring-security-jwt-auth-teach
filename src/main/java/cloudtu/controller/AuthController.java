package cloudtu.controller;

import cloudtu.controller.bean.RegisterReqDto;
import cloudtu.dao.UserDao;
import cloudtu.dao.bean.User;
import cloudtu.util.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    private UserDao userDao;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/register")
    public ResponseEntity register(@RequestBody RegisterReqDto registerReqDto){
        List<String> validateErrors = new ArrayList<>();

        if (userDao.isUserExist(registerReqDto.getUserName())) {
            validateErrors.add("userName '" + registerReqDto.getUserName() + "' is exist");
        }

        List<String> allUserRoles = Stream.of(User.Role.values()).map(role -> role.toString()).collect(Collectors.toList());
        if (!allUserRoles.contains(registerReqDto.getUserRole())) {
            validateErrors.add("userRole '" + registerReqDto.getUserRole() + "' is wrong");
        }

        if (!validateErrors.isEmpty()) {
            Map<String, Object> errorMsg = new LinkedHashMap<>();
            errorMsg.put("validateErrors", validateErrors);

            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorMsg);
        }

        User user = new User(registerReqDto.getUserName(), passwordEncoder.encode(registerReqDto.getUserPassword()),
                User.Role.valueOf(registerReqDto.getUserRole()));
        userDao.addUser(user);

        return new ResponseEntity(HttpStatus.OK);
    }

    @PostMapping("/login")
    public ResponseEntity login(@RequestParam String userName, @RequestParam String userPassword){
        Authentication authAfterSuccessLogin = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(userName, userPassword));
        SecurityContextHolder.getContext().setAuthentication(authAfterSuccessLogin);

        List<String> userRoles = authAfterSuccessLogin.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).collect(Collectors.toList());

        Map<String, Object> respResult = new LinkedHashMap<>();
        respResult.put("userName", userName);
        respResult.put("userPassword", userPassword);
        respResult.put("userRoles", userRoles);
        respResult.put("token", jwtUtil.createToken(userName, userRoles));

        return ResponseEntity.ok(respResult);
    }

    @GetMapping("/logout")
    public ResponseEntity logout(){
        SecurityContextHolder.clearContext();
        return new ResponseEntity(HttpStatus.OK);
    }
}
