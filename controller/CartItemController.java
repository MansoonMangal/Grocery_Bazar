package com.groceryBazar.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.groceryBazar.exception.CartItemException;
import com.groceryBazar.exception.UserException;
import com.groceryBazar.model.CartItem;
import com.groceryBazar.model.User;
import com.groceryBazar.response.ApiResponse;
import com.groceryBazar.service.CartItemService;
import com.groceryBazar.service.UserService;

@RestController
@RequestMapping("/api/cart_items")
public class CartItemController {

	private CartItemService cartItemService;
	private UserService userService;
	
	public CartItemController(CartItemService cartItemService, UserService userService) {
		this.cartItemService=cartItemService;
		this.userService=userService;
	}
	

}
