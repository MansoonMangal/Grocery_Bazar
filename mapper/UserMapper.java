package com.groceryBazar.mapper;

import com.groceryBazar.dto.OrderDto;
import com.groceryBazar.dto.OrderItemDto;
import com.groceryBazar.dto.UserDto;
import com.groceryBazar.model.Order;
import com.groceryBazar.model.OrderItem;
import com.groceryBazar.model.User;

public class UserMapper {

    public static UserDto toUserDto(User user){
        UserDto userDto = new UserDto();
        userDto.setId(user.getId());
        userDto.setFullName(user.getFullName());
        userDto.setEmail(user.getEmail());
        return userDto;
    }

}
