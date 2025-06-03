package com.groceryBazar.service;

import java.util.List;

import com.groceryBazar.exception.UserException;
import com.groceryBazar.model.User;

public interface UserService {

	public User findUserProfileByJwt(String jwt) throws UserException;
	
	public User findUserByEmail(String email) throws UserException;


}
