package cloudtu.security;

import cloudtu.dao.UserDao;
import cloudtu.dao.bean.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    private static final Logger logger = LoggerFactory.getLogger(UserDetailsServiceImpl.class);

    @Autowired
    UserDao userDao;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userDao.findUser(username);
        if (user == null){
            logger.warn("User Not Found with username : " + username);
            throw new UsernameNotFoundException("User Not Found with username : " + username);
        }

        return new UserDetailsImpl(user.getName(), user.getPassword(), new SimpleGrantedAuthority(user.getRole().toString()));
    }

}
