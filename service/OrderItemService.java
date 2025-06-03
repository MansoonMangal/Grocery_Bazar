package com.groceryBazar.service;


import com.groceryBazar.exception.OrderException;
import com.groceryBazar.model.OrderItem;
import com.groceryBazar.model.Product;

public interface OrderItemService {

	OrderItem getOrderItemById(Long id) throws Exception;
	


}
