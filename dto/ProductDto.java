package com.groceryBazar.dto;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import com.groceryBazar.model.Category;
import com.groceryBazar.model.Review;
import com.groceryBazar.model.Seller;

@Data
public class ProductDto {

    private Long id;

    private String title;

    private String description;

    private int mrpPrice;

    private int sellingPrice;

    private int discountPercent;

    private int quantity;

    private String color;

    private List<String> images = new ArrayList<>();

    private int numRatings;

    private LocalDateTime createdAt;

    private String Sizes;


}
