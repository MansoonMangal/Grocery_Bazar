package com.groceryBazar.response;

import com.groceryBazar.dto.OrderHistory;
import com.groceryBazar.model.Cart;
import com.groceryBazar.model.Order;
import com.groceryBazar.model.Product;

import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class FunctionResponse {
    private String functionName;
    private Cart userCart;
    private OrderHistory orderHistory;
    private Product product;
}
