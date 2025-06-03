package com.groceryBazar.service;

import com.groceryBazar.exception.CartItemException;
import com.groceryBazar.exception.UserException;
import com.groceryBazar.model.Cart;
import com.groceryBazar.model.CartItem;
import com.groceryBazar.model.Product;


public interface CartItemService {
	
	public CartItem updateCartItem(Long userId, Long id,CartItem cartItem) throws CartItemException, UserException;
	
	public void removeCartItem(Long userId,Long cartItemId) throws CartItemException, UserException;
	
	public CartItem findCartItemById(Long cartItemId) throws CartItemException;
	
}
