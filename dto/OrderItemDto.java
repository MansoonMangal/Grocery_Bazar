package com.groceryBazar.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.groceryBazar.model.Order;
import com.groceryBazar.model.Product;

import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToOne;
import lombok.Data;

@Data
public class OrderItemDto {

    private Long id;

    private ProductDto product;

    private String size;

    private int quantity;

    private Integer mrpPrice;

    private Integer sellingPrice;

    private Long userId;

}
