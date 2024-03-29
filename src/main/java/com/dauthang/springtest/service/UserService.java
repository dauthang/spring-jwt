package com.dauthang.springtest.service;

import com.dauthang.springtest.domain.Role;
import com.dauthang.springtest.domain.User;

import java.util.List;

public interface UserService {
    User saveUser(User user);
    Role saveRole(Role role);
    void addRoleToUser(String username, String roleName);
    User getUser(String username);
    List<User> getUser();
}
