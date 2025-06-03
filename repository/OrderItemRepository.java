package com.groceryBazar.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.groceryBazar.model.OrderItem;

public interface OrderItemRepository extends JpaRepository<OrderItem, Long> {

}
