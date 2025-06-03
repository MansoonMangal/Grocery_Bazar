package com.groceryBazar.service;

import com.groceryBazar.exception.ProductException;
import com.groceryBazar.model.Cart;
import com.groceryBazar.model.CartItem;
import com.groceryBazar.model.Product;
import com.groceryBazar.model.User;
import com.groceryBazar.request.AddItemRequest;

public interface CartService {
	
	public CartItem addCartItem(User user,
								Product product,
								String size,
								int quantity) throws ProductException;
	
	public Cart findUserCart(User user);

}
