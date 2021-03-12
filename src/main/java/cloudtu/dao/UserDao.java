package cloudtu.dao;

import cloudtu.dao.bean.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

@Repository
public class UserDao {
    private static final Logger logger = LoggerFactory.getLogger(UserDao.class);

    // 用 Map 來模擬 in memory DB，不將資料真的寫到後端 DB
    // 資料結構是 Map<userName, User object>
    private static Map<String, User> userDb = new TreeMap<>();

    public void addUser(User user) {
        synchronized (userDb) {
            userDb.put(user.getName(), user);
        }
        logger.debug("userDb : {}", userDb);
    }

    public User findUser(String userName) {
        return userDb.get(userName);
    }

    public boolean isUserExist(String userName) {
        return userDb.get(userName) == null ? false : true;
    }

    public List<User> findAllUsers() {
        return new ArrayList<>(userDb.values());
    }
}
