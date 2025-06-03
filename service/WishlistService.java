package com.groceryBazar.service;


import java.util.Optional;

import com.groceryBazar.exception.WishlistNotFoundException;
import com.groceryBazar.model.Product;
import com.groceryBazar.model.User;
import com.groceryBazar.model.Wishlist;

public interface WishlistService {

    Wishlist createWishlist(User user);

    Wishlist getWishlistByUserId(User user);

    Wishlist addProductToWishlist(User user, Product product) throws WishlistNotFoundException;

}

